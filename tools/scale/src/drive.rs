//! `drive`: the load model (`load`) on the placed agents from every
//! driver host, each driver a user unit running `vos-scale drive-local`
//! (`engine`) on its share of the users and the rate. Each agent's leader
//! is read from the nodes first, so calls go to it and queries to a
//! follower.

use std::path::Path;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use vos_abi::ids::AgentId;
use vos_wire::ingress::Response;

use crate::agents::{Agents, Placed};
use crate::deploy::{Deployed, DeployedNode};
use crate::hosts::{self, Unit};
use crate::inventory::Inventory;
use crate::load::Model;
use crate::runs::Run;

/// What every driver runs, and its share.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plan {
    pub nodes: Vec<DeployedNode>,
    /// The `K` ledger shards, each with its leader as last read.
    pub shards: Vec<Placed>,
    /// The idle agents: called only by the readers' share.
    #[serde(default)]
    pub idle: Vec<Placed>,
    /// The stand-in identity agent, if the run has one.
    pub identity: Option<Placed>,
    pub model: Model,
    pub secs: u64,
    pub every_s: u64,
    /// This driver's index among `drivers`.
    pub driver: u64,
    pub drivers: u64,
    /// The space's window clock, origin and length in ms (no origin known:
    /// both 0), and `D`, how long past a window's boundary it closes.
    pub window: (u64, u64, u64),
    /// The driver's capacity probe, set by hand in a plan given to
    /// `drive-local`: every request goes to a node that does not
    /// replicate its agent, which answers `Elsewhere` at once, before any
    /// signature check. The driver does all its work (the plan, the
    /// signatures, the requests, the answers), the nodes almost none:
    /// its own cost at its rate, apart from theirs. It needs a node
    /// outside every called agent's replicas, and writes no identity rows
    /// (that agent is on every node).
    #[serde(default)]
    pub probe: bool,
    /// The seed, in hex, of the key the driver presents to the nodes'
    /// APIs over QUIC, which every node admits: one connection a node, a
    /// stream a request.
    pub driver_key: String,
}

impl Plan {
    /// How long past the load a driver waits for its last answers: past a
    /// window and its close when reads at a cut wait for one.
    pub fn drain_ms(&self) -> u64 {
        if self.model.reads_at_cuts() {
            self.window.1 + self.window.2 + 90_000
        } else {
            30_000
        }
    }
}

/// A send this far behind its schedule is late: the driver, not the
/// nodes, set its latency's floor.
pub const LATE_US: u64 = 10_000;

/// Run this driver's share of `plan`, writing its record to `out`.
pub fn run_local(plan: &Plan, out: &Path) -> Result<(), String> {
    crate::engine::run_local(plan, out)
}

/// Each agent's leader, as one of its replicas reports it: unknown when
/// none answers.
fn leaders(inventory: &Inventory, deployed: &Deployed, placed: &mut [Placed]) {
    let operators: Vec<_> = inventory
        .nodes()
        .iter()
        .map(|host| {
            deployed.node(host).and_then(|node| {
                crate::nodes::operator(inventory, node, Duration::from_secs(10)).ok()
            })
        })
        .collect();
    for agent in placed {
        agent.leader = agent.replicas.iter().find_map(|replica| {
            let operator = operators.get(usize::from(*replica) - 1)?.as_ref()?;
            match operator.status(AgentId(agent.agent)) {
                Ok(Response::Status(status)) => status.leader,
                _ => None,
            }
        });
    }
}

/// The load `drive` offers.
pub struct Load {
    pub model: Model,
    pub secs: u64,
    /// The personal agents' wakes beside it, when the space has them.
    pub personal: Option<PersonalLoad>,
}

/// The personal agents' load: each device wakes once a period.
#[derive(Clone, Copy, Debug)]
pub struct PersonalLoad {
    pub period_s: u64,
    /// The share of pushes at the largest envelope.
    pub full_share: f64,
}

/// Start the personal agents' load on every driver host, each on its share
/// of the agents: the units started.
fn start_personal(
    inventory: &Inventory,
    run: &Run,
    deployed: &Deployed,
    load: &Load,
    driver_key: &str,
) -> Result<Vec<String>, String> {
    let Some(personal) = load.personal else {
        return Ok(Vec::new());
    };
    let personals = crate::personal::Personals::read(inventory)
        .ok_or("a personal load without personal agents: create them first")?;
    let drivers = inventory.drivers();
    let mut started = Vec::new();
    for (index, host) in drivers.iter().enumerate() {
        let plan = crate::personal::Plan {
            nodes: deployed.nodes.clone(),
            agents: personals
                .agents
                .iter()
                .skip(index)
                .step_by(drivers.len())
                .cloned()
                .collect(),
            seed: personals.seed,
            secs: load.secs,
            period_s: personal.period_s,
            every_s: inventory.harness.every_s,
            full_share: personal.full_share,
            driver_key: driver_key.to_string(),
        };
        let local = run.file(&format!("personal-{}.json", host.name));
        std::fs::write(&local, serde_json::to_string(&plan).expect("json"))
            .map_err(|error| format!("{}: {error}", local.display()))?;
        let remote = format!("{}/drive/{}.personal-plan.json", host.dir, run.id);
        hosts::push(host, &local, &remote)?;
        let unit = Unit {
            name: host.unit("personal"),
            memory_max: "2G",
            stdout: format!("{}/logs/{}.personal.log", host.dir, run.id),
            stderr: format!("{}/logs/{}.personal.log", host.dir, run.id),
            cores: host.cores.as_deref(),
            env: Vec::new(),
            command: vec![
                format!("{}/bin/vos-scale", host.dir),
                "personal-local".into(),
                "--plan".into(),
                remote,
                "--out".into(),
                format!("{}/drive/{}.personal.jsonl", host.dir, run.id),
            ],
            runtime_max_s: load.secs + 600,
        };
        hosts::run(host, &unit.start_script())?;
        started.push(host.name.clone());
    }
    eprintln!(
        "{} personal agents wake once every {} s for {} s, from {} drivers",
        personals.agents.len(),
        personal.period_s,
        load.secs,
        drivers.len()
    );
    Ok(started)
}

/// Run `load` from every driver host at once, each on its share of the
/// users and the rate, and wait for them all to end: their records in the
/// run's `hosts/<name>/`.
pub fn drive(inventory: &Inventory, run: &Run, load: &Load) -> Result<(), String> {
    let deployed = Deployed::read(inventory)?;
    let mut agents = Agents::read(inventory)?;
    let drivers = inventory.drivers();
    if drivers.is_empty() {
        return Err("no driver host in the inventory".into());
    }
    load.model.validate(agents.agents.len())?;
    load.model
        .check_representative(agents.representative.is_some())?;
    let driver_key = hex::encode(crate::nodes::driver_seed(inventory)?);
    leaders(inventory, &deployed, &mut agents.agents);
    if load.model.readers > 0.0 {
        leaders(inventory, &deployed, &mut agents.idle);
    }
    if let Some(identity) = &mut agents.identity {
        leaders(inventory, &deployed, std::slice::from_mut(identity));
    }
    let length = deployed.window_ms;
    let window = (
        deployed.origin_ms,
        if deployed.origin_ms > 0 { length } else { 0 },
        (length / 5).min(vos_abi::vos_anchor::MAX_REPRESENTATIVE_DELAY_MS),
    );
    let mut drain_s = 0;
    for (index, host) in drivers.iter().enumerate() {
        let plan = Plan {
            nodes: deployed.nodes.clone(),
            shards: agents.agents.clone(),
            idle: if load.model.readers > 0.0 {
                agents.idle.clone()
            } else {
                Vec::new()
            },
            identity: agents.identity.clone(),
            model: load.model.clone(),
            secs: load.secs,
            every_s: inventory.harness.every_s,
            driver: index as u64,
            drivers: drivers.len() as u64,
            window,
            probe: false,
            driver_key: driver_key.clone(),
        };
        drain_s = plan.drain_ms().div_ceil(1_000);
        let local = run.file(&format!("drive-{}.json", host.name));
        std::fs::write(&local, serde_json::to_string_pretty(&plan).expect("json"))
            .map_err(|error| format!("{}: {error}", local.display()))?;
        let remote = format!("{}/drive/{}.plan.json", host.dir, run.id);
        hosts::push(host, &local, &remote)?;
        let unit = Unit {
            name: host.unit("drive"),
            memory_max: host.memory_max(&inventory.harness),
            stdout: format!("{}/logs/{}.drive.log", host.dir, run.id),
            stderr: format!("{}/logs/{}.drive.log", host.dir, run.id),
            cores: host.cores.as_deref(),
            env: Vec::new(),
            command: vec![
                format!("{}/bin/vos-scale", host.dir),
                "drive-local".into(),
                "--plan".into(),
                remote,
                "--out".into(),
                format!("{}/drive/{}.drive.jsonl", host.dir, run.id),
            ],
            // Its load and its drain, then a margin to write.
            runtime_max_s: load.secs + drain_s + 300,
        };
        hosts::run(host, &unit.start_script())?;
    }
    let personal = start_personal(inventory, run, &deployed, load, &driver_key)?;
    eprintln!(
        "{} drivers offer U·a·r = {} · {} · {} = {:.0} calls a second for {} s",
        drivers.len(),
        load.model.users,
        load.model.active,
        load.model.per_user,
        load.model.rate(),
        load.secs
    );
    let ended = hosts::wait_for(
        "the drivers end",
        Duration::from_secs(load.secs + drain_s + 120),
        Duration::from_secs(2),
        || {
            for host in &drivers {
                let mut units = vec![host.unit("drive")];
                if personal.contains(&host.name) {
                    units.push(host.unit("personal"));
                }
                for unit in units {
                    let state = hosts::run(host, &hosts::state_script(&unit))?;
                    if matches!(state.trim(), "active" | "activating" | "deactivating") {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        },
    );
    if ended.is_err() {
        for host in &drivers {
            hosts::run(
                host,
                &hosts::stop_script(&[host.unit("drive"), host.unit("personal")]),
            )?;
        }
    }
    ended?;
    for host in &drivers {
        if !personal.contains(&host.name) {
            continue;
        }
        let to = run.dir.join("hosts").join(&host.name);
        hosts::pull(
            host,
            &format!("{}/drive/{}.personal.jsonl", host.dir, run.id),
            &to,
        )?;
        hosts::pull(
            host,
            &format!("{}/logs/{}.personal.log", host.dir, run.id),
            &to,
        )?;
        let record = std::fs::read_to_string(to.join(format!("{}.personal.jsonl", run.id)))
            .unwrap_or_default();
        let totals: Vec<serde_json::Value> = record
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|line| line["total"] == true)
            .collect();
        if totals.is_empty() {
            return Err(format!(
                "{}: the personal load ended without its totals: see {}",
                host.name,
                to.join(format!("{}.personal.log", run.id)).display()
            ));
        }
        for total in totals.iter().filter(|line| line["kind"] != "all") {
            eprintln!(
                "{}: personal {} {} sent, {} ok, {} errors {}, p50 {} us, p99 {} us",
                host.name,
                total["kind"],
                total["sent"],
                total["ok"],
                total["errors"],
                total["by_error"],
                total["p50_us"],
                total["p99_us"]
            );
        }
    }
    for host in &drivers {
        let to = run.dir.join("hosts").join(&host.name);
        hosts::pull(
            host,
            &format!("{}/drive/{}.drive.jsonl", host.dir, run.id),
            &to,
        )?;
        let record =
            std::fs::read_to_string(to.join(format!("{}.drive.jsonl", run.id))).unwrap_or_default();
        let total = record
            .lines()
            .last()
            .and_then(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .filter(|line| line["total"] == true);
        match total {
            Some(total) => eprintln!(
                "{}: {} ok, {} errors, p50 {} us, p99 {} us, the mix off its target by {} at most",
                host.name,
                total["ok"],
                total["errors"],
                total["p50_us"],
                total["p99_us"],
                total["mix"]["worst_error"]
            ),
            None => {
                hosts::pull(
                    host,
                    &format!("{}/logs/{}.drive.log", host.dir, run.id),
                    &to,
                )?;
                return Err(format!(
                    "{}: the driver ended without its total: see {}",
                    host.name,
                    to.join(format!("{}.drive.log", run.id)).display()
                ));
            }
        }
    }
    Ok(())
}
