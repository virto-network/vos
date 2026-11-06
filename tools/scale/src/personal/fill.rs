//! The full agent: filled to its quota with envelopes of the largest size
//! from a few sessions at once, its log compacted, then one replica
//! replaced by a spare node, which installs the agent from a snapshot; the
//! install timed from the replacement's start to the spare's replica
//! applying the leader's commit, and a read served there through the onion.

use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use smol::LocalExecutor;
use vos_node::client::Operator;
use vos_wire::Encode;
use vos_wire::ids::AgentId;
use vos_wire::ingress::{ReplicaStatus, Response};
use vos_wire::personal::{Envelope, MAX_ENVELOPE, PersonalError, Pushed};

use super::Personals;
use super::load::{SCOPE, envelope};
use super::onion::{Answer, Device, Nodes};
use crate::agents::Mix;
use crate::deploy::Deployed;
use crate::histogram::Histogram;
use crate::inventory::Inventory;
use crate::runs::Run;

/// Sessions pushing at once.
const SESSIONS: usize = 4;
/// How long the leader's log may take to compact past the fill.
const COMPACTED: Duration = Duration::from_secs(120);
/// How long the spare's replica may take to catch up.
const INSTALLED: Duration = Duration::from_secs(300);

/// What the fill, the replacement and the install came to, in the run's
/// `fill.json`.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Fill {
    pub agent: u32,
    pub from_ms: u64,
    /// The leader's commit before the fill: a snapshot past it holds the
    /// fill's envelopes.
    pub commit_before: u64,
    pub pushes: u64,
    pub bytes: u64,
    pub fill_ms: u64,
    pub push_p50_us: u64,
    pub push_p99_us: u64,
    /// What ended the fill: the quota, or an error.
    pub stopped_by: BTreeMap<String, u64>,
    /// The leader's replica after the fill.
    pub leader: Option<u8>,
    pub leader_commit: u64,
    pub leader_log_start: u64,
    pub compacted_ms: Option<u64>,
    pub remove: u8,
    pub add: u8,
    pub replace_answer: String,
    pub replace_ms: u64,
    /// From the replacement's start to the spare's replica applying the
    /// leader's commit: its snapshot installed.
    pub installed_ms: Option<u64>,
    pub installed: Option<(u64, u64)>,
    /// A `since` read at the spare through the onion: envelopes and bytes.
    pub served: Option<(u64, u64)>,
    pub error: Option<String>,
    pub to_ms: u64,
    /// The gate: filled to the quota, the spare's replica installed from a
    /// snapshot past the fill, within 30 s of the replacement's start.
    pub passed: bool,
}

/// The longest a full agent's snapshot may take to install.
pub const INSTALL_LIMIT_MS: u64 = 30_000;

/// The replica of `agent` that leads in the latest term among `replicas`.
fn leader_of(
    operators: &[Operator],
    agent: AgentId,
    replicas: &[u8],
) -> Option<(u8, ReplicaStatus)> {
    replicas
        .iter()
        .filter_map(|replica| {
            let status = status(&operators[usize::from(*replica) - 1], agent)?;
            status.leads.then_some((*replica, status))
        })
        .max_by_key(|(_, status)| status.term)
}

fn status(operator: &Operator, agent: AgentId) -> Option<ReplicaStatus> {
    match operator.status(agent) {
        Ok(Response::Status(status)) => Some(status),
        _ => None,
    }
}

/// Push envelopes of the largest size until the quota refuses one.
fn push_full(
    nodes: &Rc<Nodes>,
    device: &Rc<Device>,
    seed: u64,
    fill: &mut Fill,
) -> Result<(), String> {
    let executor = LocalExecutor::new();
    let done = Rc::new(AtomicBool::new(false));
    let started = Instant::now();
    let results = smol::block_on(executor.run(async {
        nodes.learn_time().await?;
        let tasks: Vec<_> = (0..SESSIONS)
            .map(|session| {
                let (nodes, device, done) = (nodes.clone(), device.clone(), done.clone());
                executor.spawn(async move {
                    let mut mix = Mix(seed ^ (0xf111 + session as u64));
                    let mut name = [0; 16];
                    name[..8].copy_from_slice(&mix.next().to_le_bytes());
                    let mut opened = device.session(name, nodes.now());
                    let mut sequence = 1;
                    let mut latency = Histogram::default();
                    let mut pushed = (0u64, 0u64);
                    let mut stopped = BTreeMap::new();
                    while !done.load(Ordering::Relaxed) && !crate::hosts::interrupted() {
                        let bytes = envelope(&mut mix, 0, MAX_ENVELOPE);
                        let call = device.call(opened, sequence, "push", bytes.encode());
                        let sent = Instant::now();
                        let answer = nodes
                            .call(device.agent, &device.replicas, &device.leader, &call)
                            .await;
                        latency.record(sent.elapsed().as_micros() as u64);
                        match &answer {
                            Ok(Response::Ran { .. }) => sequence += 1,
                            // Its fate unknown, the push may have spent
                            // the sequence: a new session goes on.
                            Err(_) => {
                                name[8..].copy_from_slice(&mix.next().to_le_bytes());
                                opened = device.session(name, nodes.now());
                                sequence = 1;
                            }
                            Ok(_) => {}
                        }
                        match Answer::<Pushed>::of(&answer) {
                            Answer::Reply(_) => {
                                pushed.0 += 1;
                                pushed.1 += bytes.len() as u64;
                            }
                            Answer::Error(PersonalError::Quota) => {
                                done.store(true, Ordering::Relaxed);
                                *stopped.entry("Quota".to_string()).or_insert(0) += 1;
                            }
                            other => {
                                *stopped.entry(other.name()).or_insert(0) += 1;
                                if stopped.values().sum::<u64>() > 16 {
                                    done.store(true, Ordering::Relaxed);
                                }
                            }
                        }
                    }
                    (pushed, latency, stopped)
                })
            })
            .collect();
        let mut all = Vec::new();
        for task in tasks {
            all.push(task.await);
        }
        Ok::<_, String>(all)
    }))?;
    let mut latency = Histogram::default();
    for ((pushes, bytes), histogram, stopped) in results {
        fill.pushes += pushes;
        fill.bytes += bytes;
        latency.add(&histogram);
        for (name, count) in stopped {
            *fill.stopped_by.entry(name).or_insert(0) += count;
        }
    }
    fill.fill_ms = started.elapsed().as_millis() as u64;
    fill.push_p50_us = latency.quantile(0.5);
    fill.push_p99_us = latency.quantile(0.99);
    Ok(())
}

fn fill_and_replace(
    inventory: &Inventory,
    personals: &Personals,
    fill: &mut Fill,
) -> Result<(), String> {
    let full = personals.full.as_ref().ok_or("no full agent")?;
    let deployed = Deployed::read(inventory)?;
    let client = crate::nodes::driver_seed(inventory)?;
    let nodes = Rc::new(Nodes::new(&deployed.nodes, client)?);
    let device = Rc::new(Device::sync(personals.seed, full));
    let agent = AgentId(full.agent);
    fill.agent = full.agent;
    let operators: Vec<Operator> = inventory
        .nodes()
        .iter()
        .map(|host| {
            let node = deployed
                .node(host)
                .ok_or_else(|| format!("{}: not deployed", host.name))?;
            crate::nodes::operator(inventory, node, Duration::from_secs(90))
        })
        .collect::<Result<_, String>>()?;
    fill.commit_before =
        leader_of(&operators, agent, &full.replicas).map_or(0, |(_, status)| status.commit);
    push_full(&nodes, &device, personals.seed, fill)?;
    eprintln!(
        "the fill: agent {} took {} envelopes, {:.1} MiB, in {:.1} s; stopped by {:?}",
        full.agent,
        fill.pushes,
        fill.bytes as f64 / (1 << 20) as f64,
        fill.fill_ms as f64 / 1e3,
        fill.stopped_by
    );
    // The leader's log compacted past the fill: a new replica needs its
    // snapshot.
    let compacting = Instant::now();
    let mut leading = None;
    while compacting.elapsed() < COMPACTED && !crate::hosts::interrupted() {
        leading = leader_of(&operators, agent, &full.replicas);
        if let Some((_, status)) = &leading
            && status.log_start > fill.commit_before
        {
            fill.compacted_ms = Some(compacting.elapsed().as_millis() as u64);
            break;
        }
        std::thread::sleep(Duration::from_secs(1));
    }
    let (leader, led) = leading.ok_or("no replica of the full agent leads")?;
    fill.leader = Some(leader);
    fill.leader_commit = led.commit;
    fill.leader_log_start = led.log_start;
    if fill.compacted_ms.is_none() {
        eprintln!(
            "the fill: the leader's log not compacted past the fill within {} s: the spare may replay it",
            COMPACTED.as_secs()
        );
    }
    let spare = inventory
        .nodes()
        .iter()
        .position(|host| host.spare)
        .ok_or("no spare node in the inventory: no replacement")? as u8
        + 1;
    let remove = *full
        .replicas
        .iter()
        .find(|replica| **replica != leader)
        .expect("three replicas");
    fill.remove = remove;
    fill.add = spare;
    let at_spare = &operators[usize::from(spare) - 1];
    let started = Instant::now();
    std::thread::scope(|scope| {
        let replaced = scope.spawn(|| {
            let answer = operators[usize::from(leader) - 1].replace(agent, remove, spare);
            (format!("{answer:?}"), started.elapsed().as_millis() as u64)
        });
        while started.elapsed() < INSTALLED && !crate::hosts::interrupted() {
            if let Some(status) = status(at_spare, agent)
                && status.applied >= fill.leader_commit
            {
                fill.installed_ms = Some(started.elapsed().as_millis() as u64);
                fill.installed = Some((status.log_start, status.applied));
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        let (answer, ms) = replaced.join().expect("the replacement");
        fill.replace_answer = answer;
        fill.replace_ms = ms;
    });
    eprintln!(
        "the replacement of agent {}'s replica {remove} by node {spare}: {} in {} ms; installed at the spare in {:?} ms, its log from {:?}",
        full.agent, fill.replace_answer, fill.replace_ms, fill.installed_ms, fill.installed
    );
    // A read the spare serves, through the onion.
    let spare_node = usize::from(spare) - 1;
    let executor = LocalExecutor::new();
    let read = smol::block_on(executor.run(async {
        let query = device.query(nodes.now(), "since", (SCOPE, 0u64).encode());
        nodes.query(spare_node, agent, &query).await
    }));
    fill.served = match Answer::<Vec<Envelope>>::of(&read) {
        Answer::Reply(envelopes) => Some((
            envelopes.len() as u64,
            envelopes
                .iter()
                .map(|envelope| envelope.bytes.len() as u64)
                .sum(),
        )),
        other => {
            eprintln!("the spare's read: {}", other.name());
            None
        }
    };
    Ok(())
}

/// At `at_s` seconds, unless `stop` is set first, fill the full agent and
/// replace a replica of it, writing the run's `fill.json`.
pub fn fill_at(
    inventory: &Inventory,
    run: &Run,
    at_s: u64,
    stop: &AtomicBool,
) -> Result<(), String> {
    let personals = Personals::read(inventory).ok_or("no personal agents: create them first")?;
    let until = Instant::now() + Duration::from_secs(at_s);
    while Instant::now() < until {
        if stop.load(Ordering::Relaxed) || crate::hosts::interrupted() {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    let mut fill = Fill {
        from_ms: crate::now_ms(),
        ..Fill::default()
    };
    if let Err(error) = fill_and_replace(inventory, &personals, &mut fill) {
        eprintln!("the fill: {error}");
        fill.error = Some(error);
    }
    fill.to_ms = crate::now_ms();
    fill.passed = fill.error.is_none()
        && fill.stopped_by.contains_key("Quota")
        && fill.bytes + MAX_ENVELOPE as u64 > super::policy().bytes_new
        && fill
            .installed
            .is_some_and(|(log_start, _)| log_start > fill.commit_before)
        && fill.installed_ms.is_some_and(|ms| ms <= INSTALL_LIMIT_MS);
    std::fs::write(
        run.file("fill.json"),
        serde_json::to_string_pretty(&fill).expect("json"),
    )
    .map_err(|error| error.to_string())
}
