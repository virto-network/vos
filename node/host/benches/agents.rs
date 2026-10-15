//! Many agents on three nodes, in one process over QUIC on localhost, each
//! node on its own data directory, with the default election timeouts and
//! heartbeats:
//! - active: `AGENTS` agents (64), each on all three nodes, under
//!   closed-loop increments from `SESSIONS` sessions each (4), sent to
//!   the agent's leader: commits per second in total, a call's p50 and
//!   p99, inputs per batch and batches per writer flush, and the bytes a
//!   work result's log entry stores per input. With `HOT`, the
//!   first agent has that many sessions instead, and its calls and the
//!   others' are reported apart;
//! - idle: `IDLE` more agents (1,000), created and left alone: the
//!   process's CPU, as a share of one core, and its threads;
//! - with `FAILOVER=1`: the node leading the most groups stops, and the
//!   time until every group has a leader again; then it starts again: the
//!   time it takes to open, and the CPU while its groups catch up.
//!
//! `EXECUTORS` sets each node's executor threads (every core by default,
//! so three times the machine for nodes sharing it), `LINGER_MS` and
//! `MAX_INPUTS` its batching.
//!
//! `cargo bench -p vos-node --bench agents` (after `just build-agent
//! build-test-actors`). Data goes under `target/`: on the reference laptop
//! `/tmp` is tmpfs.

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use support::{count, cpu_ticks};
use vos_checker::calls::install_at_leader;
use vos_checker::percentiles;
use vos_checker::programs::{Programs, method};
use vos_checker::spaces::{open_node, space};
use vos_node::store::EntryKind;
use vos_node::{CallError, Config, Hooks, Node, Peers, Reply, Space};
use vos_wire::Encode;
use vos_wire::batch::Request;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, Session};
use vos_wire::peer::NodeNumber;
use vos_wire::result::Outcome;

const COUNTER: InstanceId = InstanceId(1);
const NODES: u8 = 3;
const WARM: Duration = Duration::from_secs(2);
const MEASURE: Duration = Duration::from_secs(5);
const IDLE_SETTLE: Duration = Duration::from_secs(5);
const IDLE_MEASURE: Duration = Duration::from_secs(10);

/// Writer flushes and committed batches, across the nodes.
#[derive(Default)]
struct Counts {
    flushes: AtomicU64,
    batches: AtomicU64,
}

impl Hooks for Counts {
    fn before_commit(&self) {
        self.flushes.fetch_add(1, Ordering::Relaxed);
    }

    fn after_commit(&self, _: AgentId, _: u64) -> bool {
        self.batches.fetch_add(1, Ordering::Relaxed);
        true
    }
}

/// Three nodes of one space over QUIC, each on its own directory.
struct Cluster {
    agent: Vec<u8>,
    dirs: Vec<PathBuf>,
    space: Space,
    counts: Arc<Counts>,
}

impl Cluster {
    fn new(agent: Vec<u8>, root: &std::path::Path) -> Self {
        let dirs: Vec<PathBuf> = (1..=NODES)
            .map(|number| root.join(format!("node-{number}")))
            .collect();
        let space = space(&agent, &dirs, |number| format!("http://node-{number}"));
        Self {
            agent,
            dirs,
            space,
            counts: Arc::default(),
        }
    }

    fn config(&self) -> Config {
        let mut config = Config::new(self.agent.clone());
        config.space = Some(self.space.clone());
        config.peers = Peers::Quic;
        config.hooks = Arc::clone(&self.counts) as Arc<dyn Hooks>;
        if let Some(executors) = count("EXECUTORS") {
            config.executors = executors as usize;
        }
        if let Some(linger) = count("LINGER_MS") {
            config.linger = Duration::from_millis(linger);
        }
        if let Some(inputs) = count("MAX_INPUTS") {
            config.max_inputs = inputs as usize;
        }
        config
    }

    fn open(&self, number: NodeNumber) -> Arc<Node> {
        let dir = &self.dirs[usize::from(number) - 1];
        Arc::new(open_node(number, dir, || self.config()))
    }
}

type Nodes = Vec<(NodeNumber, Arc<Node>)>;

/// The number of the node leading `agent`, among `nodes`.
fn leader(nodes: &Nodes, agent: AgentId) -> NodeNumber {
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some((number, _)) = nodes.iter().find(|(_, node)| node.leads(agent)) {
            return *number;
        }
        assert!(Instant::now() < until, "no leader for agent {}", agent.0);
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn node(nodes: &Nodes, number: NodeNumber) -> &Arc<Node> {
    &nodes
        .iter()
        .find(|(at, _)| *at == number)
        .expect("a running node")
        .1
}

fn create(nodes: &Nodes) -> AgentId {
    let until = Instant::now() + Duration::from_secs(60);
    loop {
        match nodes[0].1.create_replicated(vec![1, 2, 3]) {
            Ok(agent) | Err(CallError::Unconfirmed(agent)) => return agent,
            Err(error) => {
                assert!(Instant::now() < until, "no agent created: {error:?}");
                eprintln!("creation: {error:?}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// The process's CPU over `span`, as a share of one core.
fn cpu_over(span: Duration) -> f64 {
    let ticks = cpu_ticks();
    let started = Instant::now();
    std::thread::sleep(span);
    (cpu_ticks() - ticks) as f64 / 100.0 / started.elapsed().as_secs_f64()
}

fn threads() -> usize {
    std::fs::read_dir("/proc/self/task").unwrap().count()
}

/// One session's closed loop on `agent` until `until`: its calls'
/// latencies from `measure_from` on.
async fn session(
    nodes: Arc<Nodes>,
    agent: AgentId,
    number: u64,
    increment: MethodId,
    measure_from: Instant,
    until: Instant,
) -> Vec<Duration> {
    let mut key = [7; 32];
    key[..4].copy_from_slice(&agent.0.to_be_bytes());
    key[4..12].copy_from_slice(&number.to_be_bytes());
    let session = Session {
        key,
        name: u128::from(number).to_be_bytes(),
        t0: vos_node::wall_clock(),
    };
    let mut at = leader(&nodes, agent);
    let mut latencies = Vec::new();
    let mut sequence = 1;
    while Instant::now() < until {
        let request = Request {
            session,
            sequence,
            caller: Principal::Client(key),
            instance: COUNTER,
            method: increment,
            arguments: 1u64.encode(),
        };
        let started = Instant::now();
        match node(&nodes, at).call(agent, request).await {
            Ok(Reply::Ran(Outcome::Done(_))) => {
                if started >= measure_from {
                    latencies.push(started.elapsed());
                }
                sequence += 1;
            }
            Err(CallError::NotLeader(_) | CallError::Stopped | CallError::Busy) => {
                smol::Timer::after(Duration::from_millis(10)).await;
                at = leader(&nodes, agent);
            }
            other => panic!("agent {} session {number}: {other:?}", agent.0),
        }
    }
    latencies
}

/// The active load: each agent's sessions at once, the first agent's
/// `hot` of them when given. Its calls' latencies, and the others'.
fn load(
    nodes: &Arc<Nodes>,
    active: &[AgentId],
    sessions: u64,
    hot: Option<u64>,
    increment: MethodId,
    measure_from: Instant,
) -> (Vec<Duration>, Vec<Duration>) {
    let until = measure_from + MEASURE;
    smol::block_on(async {
        let tasks: Vec<_> = active
            .iter()
            .enumerate()
            .flat_map(|(position, &agent)| {
                let count = match hot {
                    Some(hot) if position == 0 => hot,
                    _ => sessions,
                };
                (0..count).map(move |number| (position == 0 && hot.is_some(), agent, number))
            })
            .map(|(is_hot, agent, number)| {
                let task = smol::spawn(session(
                    Arc::clone(nodes),
                    agent,
                    number,
                    increment,
                    measure_from,
                    until,
                ));
                (is_hot, task)
            })
            .collect();
        let (mut hot_latencies, mut cold_latencies) = (Vec::new(), Vec::new());
        for (is_hot, task) in tasks {
            let latencies = task.await;
            if is_hot {
                hot_latencies.extend(latencies);
            } else {
                cold_latencies.extend(latencies);
            }
        }
        (hot_latencies, cold_latencies)
    })
}

fn main() {
    let agents = count("AGENTS").unwrap_or(64);
    let sessions = count("SESSIONS").unwrap_or(4);
    let hot = count("HOT");
    let idle = count("IDLE").unwrap_or(1_000);
    let failover = count("FAILOVER").is_some_and(|on| on > 0);
    let Programs {
        agent: agent_program,
        counter,
        counter_elf,
    } = Programs::load();
    let increment = method(&counter, "increment");
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let cluster = Cluster::new(agent_program, dir.path());
    let nodes: Nodes = (1..=NODES)
        .map(|number| (number, cluster.open(number)))
        .collect();

    let started = Instant::now();
    let active: Vec<AgentId> = (0..agents).map(|_| create(&nodes)).collect();
    for &agent in &active {
        let leading = || Arc::clone(node(&nodes, leader(&nodes, agent)));
        install_at_leader(leading, agent, COUNTER, &counter_elf);
    }
    let mut leading = [0; NODES as usize];
    for &agent in &active {
        leading[usize::from(leader(&nodes, agent)) - 1] += 1;
    }
    println!(
        "{agents} agents created and installed in {:.1} s; leaders per node {leading:?}",
        started.elapsed().as_secs_f64()
    );

    let nodes = Arc::new(nodes);
    let measure_from = Instant::now() + WARM;
    let counts = Arc::clone(&cluster.counts);
    let counted = std::thread::spawn(move || {
        std::thread::sleep(measure_from.saturating_duration_since(Instant::now()));
        let flushes = counts.flushes.load(Ordering::Relaxed);
        let batches = counts.batches.load(Ordering::Relaxed);
        let cpu = cpu_over(MEASURE);
        (
            counts.flushes.load(Ordering::Relaxed) - flushes,
            counts.batches.load(Ordering::Relaxed) - batches,
            cpu,
        )
    });
    let (hot_latencies, cold_latencies) =
        load(&nodes, &active, sessions, hot, increment, measure_from);
    let (flushes, batches, cpu) = counted.join().unwrap();
    let per_second = |n: usize| n as f64 / MEASURE.as_secs_f64();
    let commits = hot_latencies.len() + cold_latencies.len();
    let (p50, p99) = percentiles(
        [&hot_latencies[..], &cold_latencies[..]].concat(),
        Duration::from_millis(1),
    );
    println!(
        "active: {agents} agents × {sessions} sessions{}: {:.0} commits per second, p50 {p50:.2} ms, p99 {p99:.2} ms, {:.0}% of one core; {:.1} inputs per batch, {:.1} batches per flush",
        hot.map(|hot| format!(" (the first × {hot})"))
            .unwrap_or_default(),
        per_second(commits),
        cpu * 100.0,
        commits as f64 / batches.max(1) as f64,
        batches as f64 / flushes.max(1) as f64,
    );
    // The work results the leaders' logs still hold, per input at the
    // run's inputs per batch.
    let (mut bytes, mut entries) = (0usize, 0usize);
    for &agent in &active {
        let log = node(&nodes, leader(&nodes, agent))
            .store()
            .raft(agent)
            .unwrap()
            .log;
        for (_, entry) in log
            .iter()
            .filter(|(_, entry)| entry.kind == EntryKind::Result)
        {
            bytes += entry.payload().len();
            entries += 1;
        }
    }
    let per_entry = bytes as f64 / entries.max(1) as f64;
    println!(
        "  a work result's log entry: {per_entry:.0} bytes, {:.0} per input",
        per_entry * batches as f64 / commits.max(1) as f64
    );
    if hot.is_some() {
        let (hot_p50, hot_p99) = percentiles(hot_latencies.clone(), Duration::from_millis(1));
        let (cold_p50, cold_p99) = percentiles(cold_latencies.clone(), Duration::from_millis(1));
        println!(
            "  the hot agent: {:.0} commits per second, p50 {hot_p50:.2} ms, p99 {hot_p99:.2} ms; the others: {:.0}, p50 {cold_p50:.2} ms, p99 {cold_p99:.2} ms",
            per_second(hot_latencies.len()),
            per_second(cold_latencies.len()),
        );
    }

    let started = Instant::now();
    let mut every = active.clone();
    every.extend((0..idle).map(|_| create(&nodes)));
    println!(
        "{idle} idle agents created in {:.1} s",
        started.elapsed().as_secs_f64()
    );
    std::thread::sleep(IDLE_SETTLE);
    println!(
        "idle: {} groups per node, {:.1}% of one core for three nodes, {} threads",
        agents + idle,
        cpu_over(IDLE_MEASURE) * 100.0,
        threads()
    );

    let mut nodes = Arc::into_inner(nodes).expect("the sessions are done");
    if failover {
        let mut led = [0usize; NODES as usize];
        for &agent in &every {
            led[usize::from(leader(&nodes, agent)) - 1] += 1;
        }
        let gone = (1..=NODES)
            .max_by_key(|number| led[usize::from(*number) - 1])
            .unwrap();
        let position = nodes
            .iter()
            .position(|(number, _)| *number == gone)
            .unwrap();
        let (_, stopped) = nodes.remove(position);
        let stopped_at = Instant::now();
        Arc::into_inner(stopped).expect("one owner").shutdown();
        for &agent in &every {
            leader(&nodes, agent);
        }
        println!(
            "failover: node {gone} led {} of {} groups; each has a leader again {:.2} s after it stopped",
            led[usize::from(gone) - 1],
            every.len(),
            stopped_at.elapsed().as_secs_f64()
        );
        let opened = Instant::now();
        let back = cluster.open(gone);
        let opening = opened.elapsed();
        nodes.push((gone, back));
        println!(
            "restart: node {gone} opened in {:.2} s with {} agents; {:.1}% of one core for three nodes over the next 5 s",
            opening.as_secs_f64(),
            every.len(),
            cpu_over(Duration::from_secs(5)) * 100.0
        );
    }
    for (_, node) in nodes {
        Arc::into_inner(node).expect("one owner").shutdown();
    }
}
