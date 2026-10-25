//! `drive`: a load on the placed agents from every driver host, each
//! driver a user unit running `vos-scale drive-local` on its share of the
//! users. This is the harness's smoke load: one method, users drawn
//! uniformly, open loop (Poisson arrivals, latency timed from the
//! scheduled send), a client and its connection per user. Users are keys
//! derived from the seed and their index, nothing stored; each user calls
//! one agent, by hash, through one of its replicas.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use vos_node::client::Client;
use vos_wire::ids::{AgentId, InstanceId};
use vos_wire::ingress::Response;

use crate::agents::{Agents, Mix, Placed};
use crate::deploy::{Deployed, DeployedNode};
use crate::histogram::Histogram;
use crate::hosts::{self, Unit};
use crate::inventory::Inventory;
use crate::nodes::target;
use crate::runs::Run;

/// What every driver runs, and its share.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plan {
    pub nodes: Vec<DeployedNode>,
    pub agents: Vec<Placed>,
    pub method: String,
    /// The calls' arguments, SCALE-encoded, in hex.
    pub args: String,
    pub users: u64,
    /// Calls a second, offered by all drivers together.
    pub rate: f64,
    pub secs: u64,
    pub seed: u64,
    pub every_s: u64,
    /// This driver's index among `drivers`.
    pub driver: u64,
    pub drivers: u64,
}

/// One user: its key and the agent it calls.
fn user(seed: u64, index: u64) -> ([u8; 32], u64) {
    let mut input = b"vos-scale user".to_vec();
    input.extend(seed.to_le_bytes());
    input.extend(index.to_le_bytes());
    let digest = vos_pvm::precompile::blake2b_256(&input);
    let pick = u64::from_le_bytes(digest[..8].try_into().expect("8 bytes"));
    (digest, pick)
}

/// A send this far behind its schedule is late: the driver, not the
/// nodes, set its latency's floor.
pub const LATE_US: u64 = 10_000;

/// What an interval saw.
#[derive(Default)]
struct Interval {
    latency: Histogram,
    errors: BTreeMap<String, u64>,
    /// Sends, and those later than [`LATE_US`] behind their schedule.
    sent: u64,
    late_sends: u64,
    /// How far behind its schedule the latest send went.
    late_us: u64,
}

impl Interval {
    fn absorb(&mut self, other: Interval) {
        self.latency.add(&other.latency);
        for (kind, count) in other.errors {
            *self.errors.entry(kind).or_default() += count;
        }
        self.sent += other.sent;
        self.late_sends += other.late_sends;
        self.late_us = self.late_us.max(other.late_us);
    }

    fn line(&self, t_ms: u64, seconds: f64, method: &str, total: bool) -> serde_json::Value {
        let ok = self.latency.count();
        let errors: u64 = self.errors.values().sum();
        serde_json::json!({
            "t_ms": t_ms,
            "total": total,
            "kind": method,
            "ok": ok,
            "errors": errors,
            "by_error": self.errors,
            "rate": ok as f64 / seconds.max(1e-9),
            "p50_us": self.latency.quantile(0.5),
            "p99_us": self.latency.quantile(0.99),
            "p999_us": self.latency.quantile(0.999),
            "late_us": self.late_us,
            "sent": self.sent,
            "late_sends": self.late_sends,
        })
    }
}

/// The name of what refused a call: its variant, or the client's error.
fn kind(answer: &Result<Response, vos_node::client::ClientError>) -> String {
    let text = match answer {
        Ok(response) => format!("{response:?}"),
        Err(error) => format!("client: {error}"),
    };
    text.split(|c: char| !(c.is_alphanumeric() || c == ':' || c == '_'))
        .next()
        .unwrap_or("?")
        .to_string()
}

/// Run this driver's share of `plan`, writing a line every interval to
/// `out` and a total at the end.
pub fn run_local(plan: &Plan, out: &Path) -> Result<(), String> {
    if plan.agents.is_empty() {
        return Err("no agents to call".into());
    }
    let arguments = hex::decode(&plan.args).map_err(|error| error.to_string())?;
    let first = &plan.agents[0];
    let targets = plan
        .nodes
        .iter()
        .map(target)
        .collect::<Result<Vec<_>, _>>()?;
    let schema = vos_node::client::schema(
        &targets[usize::from(first.replicas[0]) - 1],
        AgentId(first.agent),
        InstanceId(first.instance),
    )
    .map_err(|error| error.to_string())?
    .ok_or("nothing installed to call")?;
    let method = schema
        .method_id(&plan.method)
        .ok_or_else(|| format!("no method {}", plan.method))?;
    let mine: Vec<u64> = (0..plan.users)
        .filter(|index| index % plan.drivers == plan.driver)
        .collect();
    if mine.is_empty() {
        return Err("no users in this driver's share".into());
    }
    let workers = mine.len().min(32);
    let rate = plan.rate / plan.drivers as f64 / workers as f64;
    let interval = Mutex::new(Interval::default());
    let whole = Mutex::new(Interval::default());
    let start = Instant::now();
    let end = start + Duration::from_secs(plan.secs);
    let mut file =
        std::fs::File::create(out).map_err(|error| format!("{}: {error}", out.display()))?;
    std::thread::scope(|scope| {
        for worker in 0..workers {
            let users: Vec<u64> = mine.iter().copied().skip(worker).step_by(workers).collect();
            let (targets, arguments, interval) = (&targets, &arguments, &interval);
            scope.spawn(move || {
                let mut mix = Mix(plan.seed ^ (worker as u64) << 32 ^ plan.driver);
                let mut clients: BTreeMap<u64, (Client, &Placed)> = BTreeMap::new();
                let mut next = start;
                loop {
                    next += Duration::from_secs_f64(-(1.0 - mix.unit()).ln() / rate);
                    if next >= end {
                        return;
                    }
                    if let Some(wait) = next.checked_duration_since(Instant::now()) {
                        std::thread::sleep(wait);
                    }
                    let index = users[(mix.next() % users.len() as u64) as usize];
                    let (client, placed) = clients.entry(index).or_insert_with(|| {
                        let (key, pick) = user(plan.seed, index);
                        let placed = &plan.agents[(pick % plan.agents.len() as u64) as usize];
                        let replica =
                            placed.replicas[(index % placed.replicas.len() as u64) as usize];
                        let client = Client::new(
                            &targets[usize::from(replica) - 1],
                            SigningKey::from_bytes(&key),
                        );
                        (client, placed)
                    });
                    let late = Instant::now().saturating_duration_since(next);
                    let answer = client.call(
                        AgentId(placed.agent),
                        InstanceId(placed.instance),
                        method,
                        arguments,
                    );
                    let took = Instant::now().saturating_duration_since(next);
                    let mut interval = interval.lock().expect("the interval");
                    let late = late.as_micros() as u64;
                    interval.late_us = interval.late_us.max(late);
                    interval.sent += 1;
                    interval.late_sends += u64::from(late > LATE_US);
                    match answer {
                        Ok(Response::Ran { .. }) => {
                            interval.latency.record(took.as_micros() as u64)
                        }
                        other => *interval.errors.entry(kind(&other)).or_default() += 1,
                    }
                }
            });
        }
        scope.spawn(|| {
            let every = Duration::from_secs(plan.every_s.max(1));
            let mut last = start;
            loop {
                std::thread::sleep(Duration::from_millis(100));
                let now = Instant::now();
                if now.duration_since(last) < every && now < end + Duration::from_secs(1) {
                    continue;
                }
                let taken = std::mem::take(&mut *interval.lock().expect("the interval"));
                let line = taken.line(
                    crate::now_ms(),
                    now.duration_since(last).as_secs_f64(),
                    &plan.method,
                    false,
                );
                let _ = writeln!(file, "{line}");
                whole.lock().expect("the whole").absorb(taken);
                last = now;
                if now >= end + Duration::from_secs(1) {
                    break;
                }
            }
        });
    });
    let leftover = std::mem::take(&mut *interval.lock().expect("the interval"));
    let mut whole = whole.into_inner().expect("the whole");
    whole.absorb(leftover);
    let line = whole.line(crate::now_ms(), plan.secs as f64, &plan.method, true);
    writeln!(file, "{line}").map_err(|error| error.to_string())?;
    Ok(())
}

/// The load `drive` offers.
pub struct Load<'a> {
    pub users: u64,
    pub rate: f64,
    pub secs: u64,
    pub method: &'a str,
    pub args: &'a str,
    pub seed: u64,
}

/// Run `load` from every driver host at once, each on its share of the
/// users and the rate, and wait for them all to end: their records in the
/// run's `hosts/<name>/`.
pub fn drive(inventory: &Inventory, run: &Run, load: &Load) -> Result<(), String> {
    let deployed = Deployed::read(inventory)?;
    let agents = Agents::read(inventory)?;
    let drivers = inventory.drivers();
    if drivers.is_empty() {
        return Err("no driver host in the inventory".into());
    }
    for (index, host) in drivers.iter().enumerate() {
        let plan = Plan {
            nodes: deployed.nodes.clone(),
            agents: agents.agents.clone(),
            method: load.method.to_string(),
            args: load.args.to_string(),
            users: load.users,
            rate: load.rate,
            secs: load.secs,
            seed: load.seed,
            every_s: inventory.harness.every_s,
            driver: index as u64,
            drivers: drivers.len() as u64,
        };
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
            // Its load, then a margin to finish its calls and write.
            runtime_max_s: load.secs + 300,
        };
        hosts::run(host, &unit.start_script())?;
    }
    eprintln!(
        "{} drivers offer {} calls a second from {} users for {} s",
        drivers.len(),
        load.rate,
        load.users,
        load.secs
    );
    let ended = hosts::wait_for(
        "the drivers end",
        Duration::from_secs(load.secs + 120),
        Duration::from_secs(2),
        || {
            for host in &drivers {
                let state = hosts::run(host, &hosts::state_script(&host.unit("drive")))?;
                if matches!(state.trim(), "active" | "activating" | "deactivating") {
                    return Ok(false);
                }
            }
            Ok(true)
        },
    );
    if ended.is_err() {
        for host in &drivers {
            hosts::run(host, &hosts::stop_script(&[host.unit("drive")]))?;
        }
    }
    ended?;
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
                "{}: {} ok, {} errors, p50 {} us, p99 {} us",
                host.name, total["ok"], total["errors"], total["p50_us"], total["p99_us"]
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

#[cfg(test)]
mod tests {
    use super::{kind, user};
    use vos_wire::ingress::Response;

    #[test]
    fn users_are_derived_not_stored() {
        assert_eq!(user(1, 5), user(1, 5));
        assert_ne!(user(1, 5).0, user(1, 6).0);
        assert_ne!(user(1, 5).0, user(2, 5).0);
    }

    #[test]
    fn a_refusal_is_named_by_its_variant() {
        assert_eq!(kind(&Ok(Response::Busy)), "Busy");
        assert_eq!(kind(&Ok(Response::NotLeader { leader: None })), "NotLeader");
    }
}
