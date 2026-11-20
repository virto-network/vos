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
mod engine;
mod fault;
mod gateway;
mod histogram;
mod hosts;
mod inventory;
mod keys;
mod load;
mod nodes;
mod personal;
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

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Milliseconds since the epoch, to the microsecond.
pub fn precise_now_ms() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("after the epoch")
        .as_secs_f64()
        * 1e3
}

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
    /// The agent program's ELF (`just build-programs`).
    #[arg(long)]
    agent: Option<PathBuf>,
}

#[derive(clap::Args)]
struct AgentsArgs {
    /// Ledger shards to create, `K`, each on three nodes drawn by weight.
    #[arg(long)]
    count: u32,
    /// Idle agents to create beside them, `I`: installed, never called.
    #[arg(long, default_value_t = 0)]
    idle: u32,
    /// The stand-in identity agent's rows, `U`: created on every node with
    /// them when not 0.
    #[arg(long, default_value_t = 0)]
    identity_rows: u64,
    /// The actor installed in each (`just build-test-actors`): the shard
    /// actor by default.
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
    /// Agents created at once: each mostly waits for its group's first
    /// election.
    #[arg(long, default_value_t = agents::CREATORS)]
    creators: u32,
    #[command(flatten)]
    personal: PersonalArgs,
}

/// The personal agents a space gets beside the load's agents.
#[derive(clap::Args, Clone)]
struct PersonalArgs {
    /// Personal agents to create, `Personal` installed in each and
    /// assigned by the home's stand-in to a test device; one more is made
    /// for the fill.
    #[arg(long, default_value_t = 0)]
    personal: u32,
    /// `Personal`'s ELF (`just build-programs`).
    #[arg(long)]
    personal_elf: Option<PathBuf>,
    /// The home's stand-in, the `home` test actor (`just build-test-actors`).
    #[arg(long)]
    home_elf: Option<PathBuf>,
    /// Personal agents created at once.
    #[arg(long, default_value_t = agents::CREATORS)]
    personal_creators: u32,
}

impl PersonalArgs {
    fn request(&self, seed: u64) -> Option<personal::Request> {
        (self.personal > 0).then(|| personal::Request {
            count: self.personal,
            personal: self.personal_elf.clone().unwrap_or_else(|| {
                guest("agent/programs/target/riscv64em-vos/release/vos-personal.elf")
            }),
            home: self.home_elf.clone().unwrap_or_else(|| {
                guest("agent/test-actors/target/riscv64em-vos/release/home.elf")
            }),
            seed,
            creators: self.personal_creators,
        })
    }
}

/// The personal agents' wakes and the fill, beside the load.
#[derive(clap::Args, Clone)]
struct PersonalLoadArgs {
    /// How often each personal agent's device wakes, in seconds.
    #[arg(long, default_value_t = 900)]
    wake_s: u64,
    /// The share of pushes at the largest envelope.
    #[arg(long, default_value_t = 0.02)]
    full_share: f64,
    /// Fill the full agent to its quota and replace a replica of it by the
    /// spare node, this many seconds into the load.
    #[arg(long)]
    fill_at_s: Option<u64>,
}

#[derive(clap::Args)]
struct FaultArgs {
    /// T5: kill this node host's unit (SIGKILL) under the load, and start
    /// it again on its data.
    #[arg(long)]
    kill: Option<String>,
    /// Seconds into the load the node is killed.
    #[arg(long, default_value_t = 600, requires = "kill")]
    kill_at_s: u64,
    /// Seconds into the load it is started again.
    #[arg(long, default_value_t = 900, requires = "kill")]
    restart_at_s: u64,
}

impl FaultArgs {
    fn fault(&self, inventory: &Inventory, secs: u64) -> Result<Option<fault::Fault>, String> {
        let Some(node) = &self.kill else {
            return Ok(None);
        };
        let fault = fault::Fault {
            node: node.clone(),
            kill_at_s: self.kill_at_s,
            restart_at_s: self.restart_at_s,
        };
        fault.validate(inventory, secs)?;
        Ok(Some(fault))
    }
}

#[derive(clap::Args)]
struct LoadArgs {
    /// `U`: simulated users, each a key derived from the seed and its
    /// index.
    #[arg(long)]
    users: u64,
    /// `a`: the share of users active at once.
    #[arg(long, default_value_t = 0.05)]
    active: f64,
    /// `r`: calls a second an active user makes. The offered load is
    /// `U·a·r`.
    #[arg(long, default_value_t = 0.1, conflicts_with = "rate")]
    per_user: f64,
    /// The offered load `U·a·r` in calls a second, setting `r` to it.
    #[arg(long)]
    rate: Option<f64>,
    /// How long, on average, a user stays active, in seconds.
    #[arg(long, default_value_t = 300.0)]
    active_s: f64,
    /// The mix: each kind's share, summing to 1.
    #[arg(
        long,
        default_value = "transfer=0.8,query=0.15,workflow=0.045,cut=0.005"
    )]
    mix: String,
    /// `x`: the share of transfers to a payee in another shard; random
    /// payees' `1 − 1/K` by default.
    #[arg(long)]
    cross: Option<f64>,
    /// The users' Zipf exponent.
    #[arg(long, default_value_t = 1.0)]
    zipf: f64,
    /// Writes a second to the stand-in identity agent, when the run has
    /// one.
    #[arg(long, default_value_t = 10.0)]
    identity_hz: f64,
    /// The share of all agents, shards and idle, each reading once at a
    /// cut every window (T4's is 1%).
    #[arg(long, default_value_t = 0.0)]
    readers: f64,
    /// How long the load runs.
    #[arg(long)]
    secs: u64,
    #[arg(long, default_value_t = 1)]
    seed: u64,
}

impl LoadArgs {
    /// The model these arguments give, for `shards` ledger shards.
    fn model(&self, shards: usize) -> Result<load::Model, String> {
        let per_user = match self.rate {
            Some(rate) => rate / (self.users as f64 * self.active),
            None => self.per_user,
        };
        let model = load::Model {
            users: self.users,
            active: self.active,
            per_user,
            active_s: self.active_s,
            shares: load::Shares::parse(&self.mix)?,
            cross: self
                .cross
                .unwrap_or_else(|| load::Model::random_cross(shards)),
            zipf: self.zipf,
            identity_hz: self.identity_hz,
            readers: self.readers,
            seed: self.seed,
        };
        model.validate(shards)?;
        Ok(model)
    }
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
    Drive {
        #[command(flatten)]
        load: LoadArgs,
        #[command(flatten)]
        fault: FaultArgs,
        #[command(flatten)]
        personal: PersonalLoadArgs,
    },
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
        /// Seconds of the drivers' span left out at its start: one
        /// sampling interval by default.
        #[arg(long, conflicts_with = "from_ms")]
        ramp_s: Option<u64>,
    },
    /// The whole run from one command: deploy, up, agents, drive while
    /// polling, collect, down and report.
    Run {
        #[command(flatten)]
        deploy: DeployArgs,
        #[command(flatten)]
        load: LoadArgs,
        #[command(flatten)]
        fault: FaultArgs,
        #[command(flatten)]
        personal: PersonalArgs,
        #[command(flatten)]
        personal_load: PersonalLoadArgs,
        /// Ledger shards to create, `K`.
        #[arg(long)]
        shards: u32,
        /// Idle agents beside them, `I`.
        #[arg(long, default_value_t = 0)]
        idle: u32,
        /// Agents created at once.
        #[arg(long, default_value_t = agents::CREATORS)]
        creators: u32,
        /// Create the stand-in identity agent, with a row a user.
        #[arg(long)]
        identity: bool,
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
    /// On a driver host: its share of the personal agents' wakes.
    #[command(hide = true)]
    PersonalLocal {
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
            .unwrap_or_else(|| guest("agent/programs/target/riscv64em-vos/release/vos-agent.elf")),
        repository: repository(),
    }
}

fn agents_request(args: &AgentsArgs) -> (PathBuf, Option<PathBuf>) {
    let actor = args
        .actor
        .clone()
        .unwrap_or_else(|| guest("agent/test-actors/target/riscv64em-vos/release/shard.elf"));
    let representative = args
        .representative
        .then(|| guest("agent/programs/target/riscv64em-vos/release/vos-representative.elf"));
    (actor, representative)
}

fn make_agents(inventory: &Inventory, args: &AgentsArgs, run: Option<&Run>) -> Result<(), String> {
    let (actor, representative) = agents_request(args);
    agents::create(
        inventory,
        &agents::Request {
            count: args.count,
            idle: args.idle,
            identity_rows: args.identity_rows,
            actor: &actor,
            instance: args.instance,
            representative: representative.as_deref(),
            seed: args.seed,
            creators: args.creators,
        },
    )?;
    if let Some(request) = args.personal.request(args.seed) {
        personal::create(inventory, &request)?;
    }
    if let Some(run) = run {
        keep_agents(inventory, run)?;
    }
    Ok(())
}

/// The deployed agents, copied into `run`.
fn keep_agents(inventory: &Inventory, run: &Run) -> Result<(), String> {
    for name in ["agents.json", "personal.json"] {
        let from = deploy::Deployed::dir(inventory).join(name);
        if from.exists() {
            std::fs::copy(&from, run.file(name)).map_err(|error| error.to_string())?;
        }
    }
    Ok(())
}

/// Drive `load` while polling every node, and inject `fault` if any;
/// then collect.
fn drive_and_poll(
    inventory: &Inventory,
    run: &Run,
    load: &LoadArgs,
    fault: Option<&fault::Fault>,
    personal: &PersonalLoadArgs,
) -> Result<(), String> {
    keep_agents(inventory, run)?;
    let shards = agents::Agents::read(inventory)?.agents.len();
    let model = load.model(shards)?;
    // The personal agents wake when the space has them.
    let wakes = personal::Personals::read(inventory)
        .filter(|personals| !personals.agents.is_empty())
        .map(|_| drive::PersonalLoad {
            period_s: personal.wake_s,
            full_share: personal.full_share,
        });
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let poller = scope.spawn(|| collect::poll(inventory, run, &stop));
        let faulted = scope.spawn(|| match fault {
            Some(fault) => fault::inject(inventory, run, fault, &stop),
            None => Ok(()),
        });
        let filled = scope.spawn(|| match personal.fill_at_s {
            Some(at_s) => personal::fill_at(inventory, run, at_s, &stop),
            None => Ok(()),
        });
        let driven = drive::drive(
            inventory,
            run,
            &drive::Load {
                model,
                secs: load.secs,
                personal: wakes,
            },
        );
        if let Err(error) = personal::sample_sessions(inventory, run) {
            eprintln!("the personal agents' sessions: {error}");
        }
        // One more interval of polls past the load's end.
        let _ = hosts::wait_for(
            "the last poll",
            Duration::from_secs(inventory.harness.every_s.min(10)),
            Duration::from_millis(200),
            || Ok(false),
        );
        stop.store(true, Ordering::Relaxed);
        let polled = poller.join().expect("the poller");
        let faulted = faulted.join().expect("the fault");
        let filled = filled.join().expect("the fill");
        driven.and(polled).and(faulted).and(filled)
    })?;
    collect::gather(inventory, run)
}

fn run(cli: Cli) -> Result<(), String> {
    let inventory = || Inventory::read(&cli.inventory, &cli.exclude);
    let reached = || {
        let inventory = inventory()?;
        hosts::connect(&inventory.hosts)?;
        Ok::<_, String>(inventory)
    };
    match cli.command {
        Command::Check { json } => {
            let inventory = reached()?;
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
            let deployed = deploy::deploy(&reached()?, &artifacts(args))?;
            println!(
                "space {} on {} nodes",
                deployed.space_id,
                deployed.nodes.len()
            );
            Ok(())
        }
        Command::Up { label, force } => {
            let inventory = reached()?;
            let run = Run::new(&inventory, label.as_deref())?;
            nodes::up(&inventory, &run, force)?;
            println!("run {}", run.id);
            Ok(())
        }
        Command::Agents(args) => {
            let inventory = reached()?;
            let run = Run::open(&inventory, None).ok();
            make_agents(&inventory, &args, run.as_ref())
        }
        Command::Drive {
            load,
            fault,
            personal,
        } => {
            let inventory = reached()?;
            let fault = fault.fault(&inventory, load.secs)?;
            let run = Run::open(&inventory, None)?;
            drive_and_poll(&inventory, &run, &load, fault.as_ref(), &personal)
        }
        Command::Collect => {
            let inventory = reached()?;
            let run = Run::open(&inventory, None)?;
            keep_agents(&inventory, &run)?;
            collect::gather(&inventory, &run)
        }
        Command::Down => nodes::down(&reached()?),
        Command::Report {
            run,
            from_ms,
            to_ms,
            compare,
            ramp_s,
        } => {
            let inventory = inventory()?;
            let opened = Run::open(&inventory, run.as_deref())?;
            let summary = report::report(&opened, from_ms.zip(to_ms), ramp_s)?;
            print!("{}", report::text(&summary));
            if let Some(text) = personal::summary(&opened) {
                print!("{text}");
            }
            if let Some(other) = compare {
                let other = Run::open(&inventory, Some(&other))?;
                let other = report::report(&other, None, ramp_s)?;
                print!("\n{}", report::compare(&summary, &other));
            }
            Ok(())
        }
        Command::Run {
            deploy,
            load,
            fault,
            personal,
            personal_load,
            shards,
            idle,
            creators,
            identity,
            actor,
            representative,
            label,
            no_deploy,
            force,
        } => {
            // Refused before the deploy and the agents' creation, not
            // after them.
            let model = load.model(shards as usize)?;
            model.check_representative(representative)?;
            if personal_load.fill_at_s.is_some() && personal.personal == 0 {
                return Err("--fill-at-s fills a personal agent: give --personal".into());
            }
            let inventory = reached()?;
            let fault = fault.fault(&inventory, load.secs)?;
            // Interrupted, the run's waits end and its units stop.
            hosts::stop_on_interrupt();
            if !no_deploy {
                match deploy::deploy(&inventory, &artifacts(deploy)) {
                    Ok(deployed) => {
                        eprintln!(
                            "space {} on {} nodes",
                            deployed.space_id,
                            deployed.nodes.len()
                        )
                    }
                    Err(error) => return nodes::down(&inventory).and(Err(error)),
                }
            }
            let run = Run::new(&inventory, label.as_deref())?;
            let ran = nodes::up(&inventory, &run, force)
                .and_then(|()| {
                    let args = AgentsArgs {
                        count: shards,
                        idle,
                        identity_rows: if identity { load.users } else { 0 },
                        actor,
                        instance: 1,
                        representative,
                        seed: load.seed,
                        creators,
                        personal,
                    };
                    make_agents(&inventory, &args, Some(&run))
                })
                .and_then(|()| {
                    drive_and_poll(&inventory, &run, &load, fault.as_ref(), &personal_load)
                })
                .map(|()| {
                    // The gateway's cost, a row of its own, while the
                    // nodes still run.
                    match gateway::measure(&inventory, &run) {
                        Ok(cost) => eprintln!("{}", cost.line()),
                        Err(error) => eprintln!("the gateway's cost: {error}"),
                    }
                });
            let stopped = nodes::down(&inventory);
            // A failed run is collected too, for its logs.
            let gathered = collect::gather(&inventory, &run);
            ran.and(stopped).and(gathered)?;
            let summary = report::report(&run, None, None)?;
            print!("{}", report::text(&summary));
            if let Some(text) = personal::summary(&run) {
                print!("{text}");
            }
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
        Command::PersonalLocal { plan, out } => {
            let text = std::fs::read_to_string(&plan)
                .map_err(|error| format!("{}: {error}", plan.display()))?;
            let plan: personal::Plan =
                serde_json::from_str(&text).map_err(|error| error.to_string())?;
            personal::run_local(&plan, &out)
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
