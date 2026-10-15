//! Agents messaging across nodes: three nodes in one process over QUIC on
//! localhost, each on its own data directory, every agent replicated on its
//! own node alone, so the frames between nodes are its messages, their
//! acknowledgements and `Behind`s. Each run makes its agents afresh:
//! - **fan-in:** senders, half on node 1 and half on node 2, each driven by
//!   `SESSIONS` closed-loop sessions (8) whose every call sends one message
//!   to the one receiver, on node 3;
//! - **pairs:** senders in pairs, one on node 1 and one on node 2, each
//!   call sending one message to its partner.
//!
//! A run for each count of senders in `SENDERS` (`4,16,32`) reports:
//! - over its window, the messages sent (committed in their senders'
//!   outboxes) and applied per second, the drops at a full queue, and the
//!   requests frames per message applied and the deliveries among them:
//!   past one, messages sent again;
//! - the process's CPU, and each node's batches: their inputs, their time
//!   in refine and commit, an input's wait in its queue, and how late the
//!   node's runtime wakes;
//! - on fan-in, the receiver's loop, alone on its node: its share of the
//!   window in batches and in refine, and after the load, until every
//!   message is acknowledged, what it applied and its share in batches;
//! - the stalls: a sender's messages applied by its receiver not moving
//!   while it has sent more, past 150 ms (a `Behind`'s pace is 100 ms) and
//!   past 900 ms (a resend round), and the longest;
//! - after the load, how long until every message sent is applied, and
//!   acknowledged.
//!
//! `ROWS` picks rows (`fan-in,pairs`), `EXECUTORS` each node's executor
//! threads, `QUEUE` each agent's queue cap.
//!
//! `cargo bench -p vos-node --bench fan_in` (after `just build-agent
//! build-test-actors`). Data goes under `target/`.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use vos_checker::calls::installed;
use vos_checker::programs::{Programs, method};
use vos_checker::spaces::{open_node, space};
use vos_net::Class;
use vos_node::peer::Refusal;
use vos_node::{CallError, Config, Node, Peers, Reply};
use vos_wire::batch::Request;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, Session};
use vos_wire::ingress::Stats;
use vos_wire::peer::NodeNumber;
use vos_wire::result::Outcome;
use vos_wire::{Encode, keys};

const COUNTER: InstanceId = InstanceId(1);
const NODES: u8 = 3;
const WARM: Duration = Duration::from_secs(2);
const MEASURE: Duration = Duration::from_secs(5);
/// How often the marks are sampled for stalls.
const SAMPLE: Duration = Duration::from_millis(5);
/// How long the messages sent may take to be applied after the load.
const DRAIN: Duration = Duration::from_secs(60);
/// A stall past `Behind`'s pace, and one of a resend round.
const STALL: Duration = Duration::from_millis(150);
const ROUND: Duration = Duration::from_millis(900);

fn count(name: &str) -> Option<u64> {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
}

fn list(name: &str, default: &str) -> Vec<String> {
    std::env::var(name)
        .unwrap_or_else(|_| default.into())
        .split(',')
        .map(|item| item.trim().to_string())
        .collect()
}

type Nodes = Vec<Arc<Node>>;

fn node(nodes: &Nodes, number: NodeNumber) -> &Node {
    &nodes[usize::from(number) - 1]
}

/// An agent on node `at` alone, with `counter`, the counter's package,
/// installed.
fn agent(nodes: &Nodes, at: NodeNumber, counter: &[u8]) -> AgentId {
    let node = node(nodes, at);
    let agent = node.create_agent().unwrap();
    installed(smol::block_on(node.install(
        agent,
        COUNTER,
        counter,
        vec![],
    )));
    agent
}

/// A message route: an agent sending, and the agent it sends to, each on
/// its node.
#[derive(Clone, Copy)]
struct Pair {
    from: (AgentId, NodeNumber),
    to: (AgentId, NodeNumber),
}

/// A `u64` of `agent`'s applied state on `node`, 0 when absent.
fn mark(node: &Node, agent: AgentId, key: &[u8]) -> u64 {
    vos_checker::mark(node.store(), agent, key)
}

/// The messages `pair` sent, those its receiver applied, and those its
/// sender holds acknowledged.
fn marks(nodes: &Nodes, pair: Pair) -> (u64, u64, u64) {
    let ((from, at), (to, there)) = (pair.from, pair.to);
    (
        mark(node(nodes, at), from, &keys::pair_out(to)),
        mark(node(nodes, there), to, &keys::pair_in(from)),
        mark(node(nodes, at), from, &keys::acked(to)),
    )
}

/// One session's closed loop at `pair`'s sender until `until`, each call
/// sending one message to its receiver: the calls answered.
async fn session(
    nodes: Arc<Nodes>,
    pair: Pair,
    key: [u8; 32],
    forward: MethodId,
    until: Instant,
) -> u64 {
    let ((from, at), (to, _)) = (pair.from, pair.to);
    let session = Session {
        key,
        name: [1; 16],
        t0: vos_node::wall_clock(),
    };
    let mut sequence = 1;
    while Instant::now() < until {
        let request = Request {
            session,
            sequence,
            caller: Principal::Client(key),
            instance: COUNTER,
            method: forward,
            arguments: (to.0, COUNTER.0, 1u64).encode(),
        };
        match node(&nodes, at).call(from, request).await {
            Ok(Reply::Ran(Outcome::Done(_))) => sequence += 1,
            Err(CallError::Busy) => {
                smol::Timer::after(Duration::from_millis(1)).await;
            }
            other => panic!("agent {} session: {other:?}", from.0),
        }
    }
    sequence - 1
}

/// What the run counts, read at its window's ends.
#[derive(Clone)]
struct Counts {
    requests: u64,
    deliveries: u64,
    full: u64,
    sent: u64,
    applied: u64,
    /// Each node's.
    stats: Vec<Stats>,
}

fn counts(nodes: &Nodes, pairs: &[Pair]) -> Counts {
    let (mut sent, mut applied) = (0, 0);
    for pair in pairs {
        let (out, done, _) = marks(nodes, *pair);
        sent += out;
        applied += done;
    }
    Counts {
        requests: nodes
            .iter()
            .map(|node| node.frames_arrived(Class::Requests))
            .sum(),
        deliveries: nodes.iter().map(|node| node.messages_sent_across()).sum(),
        full: nodes.iter().map(|node| node.dropped(Refusal::Full)).sum(),
        sent,
        applied,
        stats: nodes.iter().map(|node| node.stats()).collect(),
    }
}

/// The process's CPU time so far: user and system, in clock ticks.
fn cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    // The command may hold spaces: fields count from after its `)`.
    let fields: Vec<&str> = stat[stat.rfind(')').unwrap() + 2..].split(' ').collect();
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}

/// A stage's count and total between two reads of a node's stats.
fn stage(before: &Stats, after: &Stats, name: &str) -> (u64, u64) {
    let read = |stats: &Stats| {
        let stage = stats
            .stages
            .iter()
            .find(|stage| stage.name == name)
            .expect("a stage");
        (stage.counts.iter().sum::<u64>(), stage.total)
    };
    let ((count, total), (count_after, total_after)) = (read(before), read(after));
    (count_after - count, total_after - total)
}

/// When, after the load, every message sent was applied, and when its
/// sender held it acknowledged: `None` past [`DRAIN`].
struct Drained {
    applied: Option<Instant>,
    acknowledged: Option<Instant>,
}

/// Sample `pairs` until, after the load ends at `load_ends`, every message
/// they sent is applied and acknowledged, or for [`DRAIN`] more: how long
/// each pair's applied mark stayed while its sender had sent past it, and
/// when they drained.
fn watch(nodes: &Nodes, pairs: &[Pair], load_ends: Instant) -> (Vec<Duration>, Drained) {
    let mut stalls = Vec::new();
    let mut drained = Drained {
        applied: None,
        acknowledged: None,
    };
    // Per pair: its applied mark, and since when it stayed while behind.
    let mut seen: BTreeMap<usize, (u64, Instant)> = BTreeMap::new();
    loop {
        let now = Instant::now();
        let (mut unapplied, mut unacknowledged) = (false, false);
        for (index, pair) in pairs.iter().enumerate() {
            let (out, done, acked) = marks(nodes, *pair);
            let (last, since) = seen.entry(index).or_insert((done, now));
            if done != *last || out == done {
                if done != *last {
                    stalls.push(now - *since);
                }
                (*last, *since) = (done, now);
            }
            unapplied |= out > done;
            unacknowledged |= out > acked;
        }
        if now >= load_ends {
            if !unapplied {
                drained.applied.get_or_insert(now);
            }
            if !unacknowledged {
                drained.acknowledged.get_or_insert(now);
                return (stalls, drained);
            }
        }
        if now >= load_ends + DRAIN {
            if unapplied {
                stalls.extend(seen.values().map(|(_, since)| now - *since));
            }
            return (stalls, drained);
        }
        std::thread::sleep(SAMPLE);
    }
}

/// One run: `sessions` sessions at each pair's sender, each call sending
/// one message across it.
fn run(
    name: &str,
    nodes: &Arc<Nodes>,
    pairs: &[Pair],
    receiver: Option<NodeNumber>,
    sessions: u64,
    forward: MethodId,
) {
    let measure_from = Instant::now() + WARM;
    let until = measure_from + MEASURE;
    let tasks: Vec<_> = pairs
        .iter()
        .enumerate()
        .flat_map(|(index, pair)| (0..sessions).map(move |number| (index, *pair, number)))
        .map(|(index, pair, number)| {
            let mut key = [9; 32];
            key[..8].copy_from_slice(&(index as u64).to_be_bytes());
            key[8..16].copy_from_slice(&number.to_be_bytes());
            smol::spawn(session(Arc::clone(nodes), pair, key, forward, until))
        })
        .collect();
    std::thread::sleep(measure_from.saturating_duration_since(Instant::now()));
    let before = counts(nodes, pairs);
    let cpu = cpu_ticks();
    let watching = std::thread::scope(|scope| {
        let watching = scope.spawn(|| watch(nodes, pairs, until));
        std::thread::sleep(until.saturating_duration_since(Instant::now()));
        let after = counts(nodes, pairs);
        let cpu = (cpu_ticks() - cpu) as f64 / 100.0 / MEASURE.as_secs_f64();
        let calls: u64 = smol::block_on(async {
            let mut calls = 0;
            for task in tasks {
                calls += task.await;
            }
            calls
        });
        (after, cpu, calls, watching.join().unwrap())
    });
    let (after, cpu, calls, (stalls, drained)) = watching;
    let (settled, settled_at) = (counts(nodes, pairs), Instant::now());
    let after_load = |at: Option<Instant>| match at {
        Some(at) => format!("{:.2} s", (at - until).as_secs_f64()),
        None => format!("not within {} s", DRAIN.as_secs()),
    };
    let window = MEASURE.as_secs_f64();
    let applied = after.applied - before.applied;
    let per_message = |n: u64| n as f64 / applied.max(1) as f64;
    let stalled = |at_least: Duration| stalls.iter().filter(|stall| **stall >= at_least).count();
    let longest = stalls.iter().max().copied().unwrap_or_default();
    println!(
        "{name}, {} pairs × {sessions} sessions: {calls} calls; {:.0} messages sent and {:.0} applied per second; {} full-queue drops; {:.2} requests frames and {:.2} deliveries per message applied",
        pairs.len(),
        (after.sent - before.sent) as f64 / window,
        applied as f64 / window,
        after.full - before.full,
        per_message(after.requests - before.requests),
        per_message(after.deliveries - before.deliveries),
    );
    println!("  the process: {:.0}% of one core", cpu * 100.0);
    for (number, (before, after)) in (1..).zip(before.stats.iter().zip(&after.stats)) {
        let (batches, _) = stage(before, after, "batch");
        if batches == 0 {
            continue;
        }
        let mean = |name| {
            let (count, total) = stage(before, after, name);
            total as f64 / count.max(1) as f64 / 1000.0
        };
        let (_, inputs) = stage(before, after, "batch_inputs");
        println!(
            "  node {number}: {batches} batches of {:.0} inputs, each {:.2} ms (refine {:.2} ms, commit {:.2} ms); an input queued {:.2} ms; its runtime {:.2} ms late",
            inputs as f64 / batches as f64,
            mean("batch"),
            mean("refine"),
            mean("commit"),
            mean("queued"),
            mean("late"),
        );
    }
    // The receiver leads alone on its node: its loop's share of the window,
    // and of the drain after it.
    if let Some(number) = receiver {
        let index = usize::from(number) - 1;
        let (was, then, settled_stats) = (
            &before.stats[index],
            &after.stats[index],
            &settled.stats[index],
        );
        let window_us = MEASURE.as_micros() as f64;
        let (_, batch_us) = stage(was, then, "batch");
        let (_, refine_us) = stage(was, then, "refine");
        let drain = settled_at - until;
        let (_, drain_us) = stage(then, settled_stats, "batch");
        let drained = settled.applied - after.applied;
        println!(
            "  the receiver: in batches {:.0}% of the window, in refine {:.0}%; after the load, {drained} more applied in {:.2} s, {:.0} per second, in batches {:.0}% of it",
            batch_us as f64 / window_us * 100.0,
            refine_us as f64 / window_us * 100.0,
            drain.as_secs_f64(),
            drained as f64 / drain.as_secs_f64(),
            drain_us as f64 / drain.as_micros() as f64 * 100.0,
        );
    }
    println!(
        "  stalls: {} past {} ms, {} past {} ms, the longest {:.2} s; after the load, every message applied in {}, acknowledged in {}",
        stalled(STALL),
        STALL.as_millis(),
        stalled(ROUND),
        ROUND.as_millis(),
        longest.as_secs_f64(),
        after_load(drained.applied),
        after_load(drained.acknowledged),
    );
}

/// Fresh agents for a run of `row` with `count` senders, half on node 1
/// and half on node 2, each with the counter's package installed, once
/// every node knows them: its routes, and the receiver's node for fan-in.
fn routes(
    nodes: &Nodes,
    counter: &[u8],
    row: &str,
    count: usize,
) -> (Vec<Pair>, Option<NodeNumber>) {
    let senders: Vec<(AgentId, NodeNumber)> = (0..count)
        .map(|index| {
            let at = 1 + (index % 2) as NodeNumber;
            (agent(nodes, at, counter), at)
        })
        .collect();
    let (pairs, receiver): (Vec<Pair>, _) = match row {
        "fan-in" => {
            let receiver = (agent(nodes, 3, counter), 3);
            let pairs = senders
                .iter()
                .map(|from| Pair {
                    from: *from,
                    to: receiver,
                })
                .collect();
            (pairs, Some(3))
        }
        "pairs" => {
            let pairs = senders
                .chunks(2)
                .flat_map(|two| {
                    let [one, other] = two else {
                        panic!("an even count of senders")
                    };
                    [
                        Pair {
                            from: *one,
                            to: *other,
                        },
                        Pair {
                            from: *other,
                            to: *one,
                        },
                    ]
                })
                .collect();
            (pairs, None)
        }
        other => panic!("no row {other}"),
    };
    let until = Instant::now() + Duration::from_secs(30);
    while !pairs.iter().all(|pair| {
        nodes.iter().all(|node| {
            node.placement(pair.from.0).is_some() && node.placement(pair.to.0).is_some()
        })
    }) {
        assert!(Instant::now() < until, "the nodes never learnt every agent");
        std::thread::sleep(Duration::from_millis(10));
    }
    (pairs, receiver)
}

fn main() {
    if std::env::args().any(|arg| arg == "--list") {
        return;
    }
    let rows = list("ROWS", "fan-in,pairs");
    let senders: Vec<usize> = list("SENDERS", "4,16,32")
        .iter()
        .map(|count| count.parse().expect("a count of senders"))
        .collect();
    let sessions = count("SESSIONS").unwrap_or(8);
    let Programs {
        agent: agent_program,
        counter,
        counter_elf,
    } = Programs::load();
    let forward = method(&counter, "forward");
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let dirs: Vec<_> = (1..=NODES)
        .map(|number| dir.path().join(format!("node-{number}")))
        .collect();
    let space = space(&agent_program, &dirs, |number| {
        format!("http://node-{number}")
    });
    let config = || {
        let mut config = Config::new(agent_program.clone());
        config.space = Some(space.clone());
        config.peers = Peers::Quic;
        if let Some(executors) = count("EXECUTORS") {
            config.executors = executors as usize;
        }
        if let Some(queue) = count("QUEUE") {
            config.queue = queue as usize;
        }
        config
    };
    let nodes: Nodes = (1..=NODES)
        .map(|number| Arc::new(open_node(number, &dirs[usize::from(number) - 1], config)))
        .collect();

    let nodes = Arc::new(nodes);
    for row in &rows {
        for &count in &senders {
            let (pairs, receiver) = routes(&nodes, &counter_elf, row, count);
            run(row, &nodes, &pairs, receiver, sessions, forward);
        }
    }
    for node in Arc::into_inner(nodes).expect("the sessions are done") {
        Arc::into_inner(node).expect("one owner").shutdown();
    }
}
