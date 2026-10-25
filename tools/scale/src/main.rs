//! `vos-scale`: the scale test's harness. An inventory of x86-64 LAN
//! hosts, each reached over ssh (or `localhost`, here), is checked,
//! deployed to, started and stopped; agents are placed on its nodes by
//! weight, a load driven from its driver hosts, and each run collected
//! and reported in its own directory. `run` does it all from one command.
//! The tool runs on the coordinator; `sample` and `drive-local` are what
//! it starts on the hosts.

mod agents;
mod check;
mod collect;
mod deploy;
mod drive;
mod histogram;
mod hosts;
mod inventory;
mod nodes;
mod report;
mod runs;
mod sample;

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use clap::{Parser, Subcommand};

use inventory::Inventory;
use runs::Run;

pub fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_millis() as u64
}

/// The repository this tool was built in: the default artifacts' root.
fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn guest(path: &str) -> PathBuf {
    repository().join(path)
}

#[derive(Parser)]
#[command(name = "vos-scale", about = "The scale test's harness")]
struct Cli {
    /// The inventory file.
    #[arg(short, long, default_value = "inventory.toml", global = true)]
    inventory: PathBuf,
    /// Leave this host out, as if the inventory did not list it: a run
    /// again without the slowest host. Repeat for more.
    #[arg(long, global = true)]
    exclude: Vec<String>,
    #[command(subcommand)]
    command: Command,
}

#[derive(clap::Args)]
struct DeployArgs {
    /// The directory holding the static `vos` and `vos-scale` that
    /// `just release` built.
    #[arg(long)]
    bins: Option<PathBuf>,
    /// The agent program's ELF (`just build-agent`).
    #[arg(long)]
    agent: Option<PathBuf>,
}

#[derive(clap::Args)]
struct AgentsArgs {
    /// Agents to create, each on three nodes drawn by weight.
    #[arg(long)]
    count: u32,
    /// The actor installed in each (`just build-test-actors`): the
    /// counter by default.
    #[arg(long)]
    actor: Option<PathBuf>,
    #[arg(long, default_value_t = 1)]
    instance: u32,
    /// Create the space's representative first, with its package.
    #[arg(long)]
    representative: bool,
    /// The placements' seed.
    #[arg(long, default_value_t = 1)]
    seed: u64,
}

#[derive(clap::Args)]
struct LoadArgs {
    /// Simulated users, each a key derived from the seed and its index.
    #[arg(long)]
    users: u64,
    /// Calls a second, offered by all drivers together.
    #[arg(long)]
    rate: f64,
    /// How long the load runs.
    #[arg(long)]
    secs: u64,
    /// The method each call invokes.
    #[arg(long, default_value = "increment")]
    method: String,
    /// Its arguments, SCALE-encoded, in hex: `increment(1)` by default.
    #[arg(long, default_value = "0100000000000000")]
    args: String,
    #[arg(long, default_value_t = 1)]
    seed: u64,
}

#[derive(Subcommand)]
enum Command {
    /// Probe every host: its kernel, clock offset, memory and disk, the
    /// disk's type, CPU and governor, its link's speed; refuse what would
    /// mislead a run (Wi-Fi among it). Exits 1 when a host is refused.
    Check {
        /// Also write the facts as JSON here.
        #[arg(long)]
        json: Option<PathBuf>,
    },
    /// Ship the static binaries and the agent to every host, wipe its
    /// node's data, and found a new space on the node hosts.
    Deploy(DeployArgs),
    /// Start a run: every node in its unit, every host's sampler, once
    /// the hosts pass `check` again (recorded with the run).
    Up {
        /// A label for the run's directory.
        #[arg(long)]
        label: Option<String>,
        /// Start even if a host is refused.
        #[arg(long)]
        force: bool,
    },
    /// Create agents by weight and install an actor in each.
    Agents(AgentsArgs),
    /// Drive a load from the driver hosts while polling every node.
    Drive(LoadArgs),
    /// Copy every host's record of the current run into its directory.
    Collect,
    /// Stop every unit on every host.
    Down,
    /// Summarise a run (the current one by default).
    Report {
        #[arg(long)]
        run: Option<String>,
        /// The window, in milliseconds since the epoch: the drivers' span
        /// by default.
        #[arg(long, requires = "to_ms")]
        from_ms: Option<u64>,
        #[arg(long, requires = "from_ms")]
        to_ms: Option<u64>,
        /// Another run to set beside it.
        #[arg(long)]
        compare: Option<String>,
    },
    /// The whole run from one command: deploy, up, agents, drive while
    /// polling, collect, down and report.
    Run {
        #[command(flatten)]
        deploy: DeployArgs,
        #[command(flatten)]
        load: LoadArgs,
        /// Agents to create.
        #[arg(long)]
        agents: u32,
        #[arg(long)]
        actor: Option<PathBuf>,
        #[arg(long)]
        representative: bool,
        #[arg(long)]
        label: Option<String>,
        /// Keep the deployed space: no new deploy.
        #[arg(long)]
        no_deploy: bool,
        #[arg(long)]
        force: bool,
    },
    /// On a host: sample it and its node's unit, as `up` starts it.
    #[command(hide = true)]
    Sample {
        #[arg(long)]
        unit: Option<String>,
        #[arg(long)]
        iface: Option<String>,
        #[arg(long)]
        disk: Option<String>,
        #[arg(long, default_value_t = 10)]
        every: u64,
        #[arg(long)]
        out: PathBuf,
    },
    /// On a driver host: its share of a plan, as `drive` starts it.
    #[command(hide = true)]
    DriveLocal {
        #[arg(long)]
        plan: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
}

fn artifacts(args: DeployArgs) -> deploy::Artifacts {
    deploy::Artifacts {
        bins: args
            .bins
            .unwrap_or_else(|| repository().join("target/x86_64-unknown-linux-musl/release")),
        agent: args
            .agent
            .unwrap_or_else(|| guest("agent/default/target/riscv64em-vos/release/vos-agent.elf")),
        repository: repository(),
    }
}

fn agents_request(args: &AgentsArgs) -> (PathBuf, Option<PathBuf>) {
    let actor = args
        .actor
        .clone()
        .unwrap_or_else(|| guest("agent/test-actors/target/riscv64em-vos/release/counter.elf"));
    let representative = args
        .representative
        .then(|| guest("agent/representative/target/riscv64em-vos/release/vos-representative.elf"));
    (actor, representative)
}

fn make_agents(inventory: &Inventory, args: &AgentsArgs, run: Option<&Run>) -> Result<(), String> {
    let (actor, representative) = agents_request(args);
    agents::create(
        inventory,
        &agents::Request {
            count: args.count,
            actor: &actor,
            instance: args.instance,
            representative: representative.as_deref(),
            seed: args.seed,
        },
    )?;
    if let Some(run) = run {
        keep_agents(inventory, run)?;
    }
    Ok(())
}

/// The deployed agents, copied into `run`.
fn keep_agents(inventory: &Inventory, run: &Run) -> Result<(), String> {
    let from = deploy::Deployed::dir(inventory).join("agents.json");
    if from.exists() {
        std::fs::copy(&from, run.file("agents.json")).map_err(|error| error.to_string())?;
    }
    Ok(())
}

/// Drive `load` while polling every node; then collect.
fn drive_and_poll(inventory: &Inventory, run: &Run, load: &LoadArgs) -> Result<(), String> {
    keep_agents(inventory, run)?;
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let poller = scope.spawn(|| collect::poll(inventory, run, &stop));
        let driven = drive::drive(
            inventory,
            run,
            &drive::Load {
                users: load.users,
                rate: load.rate,
                secs: load.secs,
                method: &load.method,
                args: &load.args,
                seed: load.seed,
            },
        );
        // One more interval of polls past the load's end.
        std::thread::sleep(Duration::from_secs(inventory.harness.every_s.min(10)));
        stop.store(true, Ordering::Relaxed);
        let polled = poller.join().expect("the poller");
        driven.and(polled)
    })?;
    collect::gather(inventory, run)
}

fn run(cli: Cli) -> Result<(), String> {
    let inventory = || Inventory::read(&cli.inventory, &cli.exclude);
    match cli.command {
        Command::Check { json } => {
            let inventory = inventory()?;
            let facts = check::check(&inventory);
            print!("{}", check::table(&facts));
            if let Some(path) = json {
                std::fs::write(&path, serde_json::to_string_pretty(&facts).expect("json"))
                    .map_err(|error| format!("{}: {error}", path.display()))?;
            }
            if facts.iter().any(|host| !host.refused.is_empty()) {
                return Err("a host is refused".into());
            }
            Ok(())
        }
        Command::Deploy(args) => {
            let deployed = deploy::deploy(&inventory()?, &artifacts(args))?;
            println!(
                "space {} on {} nodes",
                deployed.space_id,
                deployed.nodes.len()
            );
            Ok(())
        }
        Command::Up { label, force } => {
            let inventory = inventory()?;
            let run = Run::new(&inventory, label.as_deref())?;
            nodes::up(&inventory, &run, force)?;
            println!("run {}", run.id);
            Ok(())
        }
        Command::Agents(args) => {
            let inventory = inventory()?;
            let run = Run::open(&inventory, None).ok();
            make_agents(&inventory, &args, run.as_ref())
        }
        Command::Drive(load) => {
            let inventory = inventory()?;
            let run = Run::open(&inventory, None)?;
            drive_and_poll(&inventory, &run, &load)
        }
        Command::Collect => {
            let inventory = inventory()?;
            let run = Run::open(&inventory, None)?;
            keep_agents(&inventory, &run)?;
            collect::gather(&inventory, &run)
        }
        Command::Down => nodes::down(&inventory()?),
        Command::Report {
            run,
            from_ms,
            to_ms,
            compare,
        } => {
            let inventory = inventory()?;
            let opened = Run::open(&inventory, run.as_deref())?;
            let summary = report::report(&opened, from_ms.zip(to_ms))?;
            print!("{}", report::text(&summary));
            if let Some(other) = compare {
                let other = Run::open(&inventory, Some(&other))?;
                let other = report::report(&other, None)?;
                print!("\n{}", report::compare(&summary, &other));
            }
            Ok(())
        }
        Command::Run {
            deploy,
            load,
            agents,
            actor,
            representative,
            label,
            no_deploy,
            force,
        } => {
            let inventory = inventory()?;
            if !no_deploy {
                let deployed = deploy::deploy(&inventory, &artifacts(deploy))?;
                eprintln!(
                    "space {} on {} nodes",
                    deployed.space_id,
                    deployed.nodes.len()
                );
            }
            let run = Run::new(&inventory, label.as_deref())?;
            let ran = nodes::up(&inventory, &run, force)
                .and_then(|()| {
                    let args = AgentsArgs {
                        count: agents,
                        actor,
                        instance: 1,
                        representative,
                        seed: load.seed,
                    };
                    make_agents(&inventory, &args, Some(&run))
                })
                .and_then(|()| drive_and_poll(&inventory, &run, &load));
            let stopped = nodes::down(&inventory);
            // A failed run is collected too, for its logs.
            let gathered = collect::gather(&inventory, &run);
            ran.and(stopped).and(gathered)?;
            let summary = report::report(&run, None)?;
            print!("{}", report::text(&summary));
            println!("run {} in {}", run.id, run.dir.display());
            Ok(())
        }
        Command::Sample {
            unit,
            iface,
            disk,
            every,
            out,
        } => sample::run(
            unit.as_deref(),
            iface.as_deref(),
            disk.as_deref(),
            Duration::from_secs(every.max(1)),
            &out,
        ),
        Command::DriveLocal { plan, out } => {
            let text = std::fs::read_to_string(&plan)
                .map_err(|error| format!("{}: {error}", plan.display()))?;
            let plan: drive::Plan =
                serde_json::from_str(&text).map_err(|error| error.to_string())?;
            drive::run_local(&plan, &out)
        }
    }
}

fn main() -> ExitCode {
    match run(Cli::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("vos-scale: {error}");
            ExitCode::FAILURE
        }
    }
}
