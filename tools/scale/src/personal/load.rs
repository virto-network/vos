//! `personal-local`: one driver's share of the personal agents' load. Each
//! agent's device wakes once a period, at a phase drawn from the seed, and
//! opens a new session: `alive`, then `since` (the envelopes after the
//! last it read) on a follower, then `push` of one sealed envelope (opaque
//! random bytes, mostly 1–16 KiB, a share at the largest an envelope may
//! be). Each request is timed from its send, each wake from its schedule;
//! every interval a line a kind goes to the record, and the totals last.

use std::cell::{Cell, RefCell};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use smol::{LocalExecutor, Timer};
use vos_abi::Encode;
use vos_wire::ingress::Response;
use vos_wire::personal::{Envelope, Header, MAX_ENVELOPE, Pushed, Recorded, Scope};

use super::Member;
use super::onion::{Answer, Device, Nodes};
use crate::agents::Mix;
use crate::deploy::DeployedNode;
use crate::histogram::Histogram;

/// The scope every device pushes to and reads.
pub const SCOPE: Scope = [0x5c; 16];
/// An envelope's least and most usual sizes.
const SMALL: f64 = 1024.0;
const USUAL: f64 = 16.0 * 1024.0;
/// How long the driver waits past its last wake for the wakes in flight.
const DRAIN: Duration = Duration::from_secs(90);

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plan {
    pub nodes: Vec<DeployedNode>,
    /// The agents this driver wakes.
    pub agents: Vec<Member>,
    pub seed: u64,
    pub secs: u64,
    /// How often each device wakes.
    pub period_s: u64,
    pub every_s: u64,
    /// The share of pushes at [`MAX_ENVELOPE`].
    pub full_share: f64,
    /// The driver key's seed, in hex: a gateway every node lists.
    pub driver_key: String,
}

/// One kind's counts over an interval or the whole load.
#[derive(Default)]
struct Counts {
    sent: u64,
    ok: u64,
    by_error: BTreeMap<String, u64>,
    latency: Histogram,
    bytes: u64,
}

impl Counts {
    fn add(&mut self, other: &Counts) {
        self.sent += other.sent;
        self.ok += other.ok;
        for (name, count) in &other.by_error {
            *self.by_error.entry(name.clone()).or_default() += count;
        }
        self.latency.add(&other.latency);
        self.bytes += other.bytes;
    }

    fn line(&self, kind: &str, t_ms: u64, total: bool) -> serde_json::Value {
        serde_json::json!({
            "t_ms": t_ms,
            "kind": kind,
            "total": total,
            "sent": self.sent,
            "ok": self.ok,
            "errors": self.sent - self.ok,
            "by_error": self.by_error,
            "p50_us": self.latency.quantile(0.5),
            "p99_us": self.latency.quantile(0.99),
            "p999_us": self.latency.quantile(0.999),
            "fine": self.latency.fine_json(),
            "bytes": self.bytes,
        })
    }
}

const KINDS: [&str; 4] = ["alive", "since", "push", "wake"];

#[derive(Default)]
struct Record {
    interval: BTreeMap<&'static str, Counts>,
    total: BTreeMap<&'static str, Counts>,
    sessions: u64,
    full_pushes: u64,
    late_max_us: u64,
    in_flight: u64,
}

impl Record {
    fn count(&mut self, kind: &'static str, name: &str, latency: Duration, bytes: u64) {
        let counts = self.interval.entry(kind).or_default();
        counts.sent += 1;
        if name == "ok" {
            counts.ok += 1;
        } else {
            *counts.by_error.entry(name.to_string()).or_default() += 1;
        }
        counts.latency.record(latency.as_micros() as u64);
        counts.bytes += bytes;
    }

    /// The interval's lines, its counts added to the totals.
    fn flush(&mut self, t_ms: u64) -> Vec<serde_json::Value> {
        let mut lines = Vec::new();
        for kind in KINDS {
            let counts = self.interval.remove(kind).unwrap_or_default();
            lines.push(counts.line(kind, t_ms, false));
            self.total.entry(kind).or_default().add(&counts);
        }
        lines
    }
}

/// `len` bytes no compression shortens, as sealed bytes are.
fn sealed(mix: &mut Mix, len: usize) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(len + 8);
    while bytes.len() < len {
        bytes.extend(mix.next().to_le_bytes());
    }
    bytes.truncate(len);
    bytes
}

/// An envelope of `len` bytes in [`SCOPE`] under `epoch`.
pub fn envelope(mix: &mut Mix, epoch: u64, len: usize) -> Vec<u8> {
    let mut nonce = [0; 24];
    nonce.copy_from_slice(&sealed(mix, 24));
    let header = Header {
        scope: SCOPE,
        epoch,
        nonce,
        len_class: 0,
    };
    let mut bytes = header.to_bytes().to_vec();
    bytes.extend(sealed(mix, len.max(Header::BYTES) - Header::BYTES));
    bytes
}

/// A push's size: at the largest with `full_share`, else log-uniform over
/// 1–16 KiB.
fn size(mix: &mut Mix, full_share: f64) -> usize {
    if mix.unit() < full_share {
        return MAX_ENVELOPE;
    }
    (SMALL * (USUAL / SMALL).powf(mix.unit())) as usize
}

/// A device's state across its wakes: the last position it read.
struct Agent {
    device: Device,
    read: Cell<u64>,
    wakes: Cell<u64>,
}

/// One wake of `agent`: a new session, `alive`, `since`, `push`.
async fn wake(
    nodes: &Nodes,
    agent: &Agent,
    record: &RefCell<Record>,
    mix: &mut Mix,
    full_share: f64,
    due: Instant,
) {
    let started = Instant::now();
    record.borrow_mut().sessions += 1;
    let device = &agent.device;
    let mut name = [0; 16];
    name.copy_from_slice(&sealed(mix, 16));
    let session = device.session(name, nodes.now());
    let mut sequence = 1;
    let mut ok = true;
    // `alive`.
    let sent = Instant::now();
    let call = device.call(session, sequence, "alive", Vec::new());
    let answer = nodes
        .call(device.agent, &device.replicas, &device.leader, &call)
        .await;
    let alive = Answer::<Recorded>::of(&answer);
    record
        .borrow_mut()
        .count("alive", &alive.name(), sent.elapsed(), 0);
    match &answer {
        Ok(Response::Ran { .. }) => sequence += 1,
        _ => ok = false,
    }
    // `since`, on a follower.
    let leader = device.leader.get();
    let wakes = agent.wakes.get();
    agent.wakes.set(wakes + 1);
    let followers: Vec<usize> = device
        .replicas
        .iter()
        .copied()
        .filter(|node| *node != leader)
        .collect();
    let node = if followers.is_empty() {
        leader
    } else {
        followers[(wakes as usize) % followers.len()]
    };
    let sent = Instant::now();
    let query = device.query(nodes.now(), "since", (SCOPE, agent.read.get()).encode());
    let answer = nodes.query(node, device.agent, &query).await;
    let since = Answer::<Vec<Envelope>>::of(&answer);
    let read: u64 = match &since {
        Answer::Reply(envelopes) => {
            if let Some(last) = envelopes.last() {
                agent.read.set(agent.read.get().max(last.position));
            }
            envelopes
                .iter()
                .map(|envelope| envelope.bytes.len() as u64)
                .sum()
        }
        _ => {
            ok = false;
            0
        }
    };
    record
        .borrow_mut()
        .count("since", &since.name(), sent.elapsed(), read);
    // `push`.
    let len = size(mix, full_share);
    let bytes = envelope(mix, 0, len);
    let sent = Instant::now();
    let call = device.call(session, sequence, "push", bytes.encode());
    let answer = nodes
        .call(device.agent, &device.replicas, &device.leader, &call)
        .await;
    let pushed = Answer::<Pushed>::of(&answer);
    {
        let mut record = record.borrow_mut();
        record.count("push", &pushed.name(), sent.elapsed(), len as u64);
        if len == MAX_ENVELOPE {
            record.full_pushes += 1;
        }
    }
    ok &= matches!(pushed, Answer::Reply(_));
    record.borrow_mut().count(
        "wake",
        if ok { "ok" } else { "failed" },
        started.saturating_duration_since(due) + started.elapsed(),
        0,
    );
}

/// Run `plan`'s wakes, writing the record to `out`.
pub fn run_local(plan: &Plan, out: &Path) -> Result<(), String> {
    let client = crate::keys::hex32(&plan.driver_key)?;
    let nodes = Rc::new(Nodes::new(&plan.nodes, client)?);
    let agents: Rc<Vec<Agent>> = Rc::new(
        plan.agents
            .iter()
            .map(|member| Agent {
                device: Device::sync(plan.seed, member),
                read: Cell::new(0),
                wakes: Cell::new(0),
            })
            .collect(),
    );
    // Every wake of the load, in time order: an agent's phase, then once
    // a period.
    let period_ms = plan.period_s.max(1) * 1_000;
    let span_ms = plan.secs * 1_000;
    let mut wakes: Vec<(u64, usize)> = Vec::new();
    for (at, member) in plan.agents.iter().enumerate() {
        let phase = (Mix(plan.seed ^ member.index.wrapping_mul(0x2545_f491)).unit()
            * period_ms as f64) as u64;
        wakes.extend(
            (phase..span_ms)
                .step_by(period_ms as usize)
                .map(|due| (due, at)),
        );
    }
    wakes.sort_unstable();
    let file = std::fs::File::create(out).map_err(|error| format!("{}: {error}", out.display()))?;
    let file = Rc::new(RefCell::new(file));
    let write = |file: &RefCell<std::fs::File>, lines: Vec<serde_json::Value>| {
        let mut file = file.borrow_mut();
        for line in lines {
            let _ = writeln!(file, "{line}");
        }
        let _ = file.flush();
    };
    let record = Rc::new(RefCell::new(Record::default()));
    let executor = LocalExecutor::new();
    let every = Duration::from_secs(plan.every_s.max(1));
    let ended = Rc::new(Cell::new(false));
    let result = smol::block_on(executor.run(async {
        nodes.learn_time().await?;
        for pool in &nodes.pools {
            pool.warm().await;
        }
        eprintln!(
            "{} personal agents, {} wakes over {} s, one an agent every {} s",
            agents.len(),
            wakes.len(),
            plan.secs,
            plan.period_s
        );
        let writer = {
            let (record, ended, file) = (record.clone(), ended.clone(), file.clone());
            executor.spawn(async move {
                let mut next = Instant::now() + every;
                while !ended.get() {
                    Timer::at(next).await;
                    next += every;
                    let lines = record.borrow_mut().flush(crate::now_ms());
                    write(&file, lines);
                }
            })
        };
        let start = Instant::now();
        let mut mix = Mix(plan.seed ^ 0x5ca1e);
        let mut tasks = Vec::new();
        for (due, at) in &wakes {
            let due = start + Duration::from_millis(*due);
            let now = Instant::now();
            if due > now {
                Timer::at(due).await;
            }
            if crate::hosts::interrupted() {
                break;
            }
            let late = Instant::now().saturating_duration_since(due).as_micros() as u64;
            {
                let mut record = record.borrow_mut();
                record.late_max_us = record.late_max_us.max(late);
                record.in_flight += 1;
            }
            let (nodes, agents, record) = (nodes.clone(), agents.clone(), record.clone());
            let mut mine = Mix(mix.next());
            let full_share = plan.full_share;
            let at = *at;
            tasks.push(executor.spawn(async move {
                wake(&nodes, &agents[at], &record, &mut mine, full_share, due).await;
                record.borrow_mut().in_flight -= 1;
            }));
            tasks.retain(|task| !task.is_finished());
        }
        let drained = Instant::now() + DRAIN;
        while record.borrow().in_flight > 0 && Instant::now() < drained {
            Timer::after(Duration::from_millis(200)).await;
        }
        ended.set(true);
        writer.await;
        let mut record = record.borrow_mut();
        let now = crate::now_ms();
        let mut lines = record.flush(now);
        for kind in KINDS {
            let total = record.total.remove(kind).unwrap_or_default();
            lines.push(total.line(kind, now, true));
        }
        lines.push(serde_json::json!({
            "t_ms": now,
            "kind": "all",
            "total": true,
            "agents": agents.len(),
            "wakes": wakes.len(),
            "sessions": record.sessions,
            "full_pushes": record.full_pushes,
            "late_max_us": record.late_max_us,
            "unfinished": record.in_flight,
        }));
        Ok::<_, String>(lines)
    }));
    write(&file, result?);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{MAX_ENVELOPE, Mix, envelope, size};
    use vos_wire::personal::Header;

    #[test]
    fn envelopes_are_sized_and_parse() {
        let mut mix = Mix(3);
        let mut full = 0;
        for _ in 0..10_000 {
            let len = size(&mut mix, 0.02);
            assert!((1024..=MAX_ENVELOPE).contains(&len), "{len}");
            if len == MAX_ENVELOPE {
                full += 1;
            } else {
                assert!(len <= 16 * 1024, "{len}");
            }
        }
        assert!((100..=300).contains(&full), "{full}");
        let bytes = envelope(&mut mix, 0, 4096);
        assert_eq!(bytes.len(), 4096);
        let header = Header::parse(&bytes).unwrap();
        assert_eq!((header.scope, header.epoch), (super::SCOPE, 0));
    }
}
