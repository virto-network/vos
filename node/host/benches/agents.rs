//! Many agents on three nodes (slice 3, step 3.8), in one process over
//! QUIC on localhost, each node on its own data directory, with the
//! default election timeouts and heartbeats:
//! - active: `AGENTS` agents (64), each on all three nodes, under
//!   closed-loop increments from `SESSIONS` sessions each (4), sent to
//!   the agent's leader: commits per second in total, and a call's p50 and
//!   p99;
//! - idle: `IDLE` more agents (1,000), created and left alone: the
//!   process's CPU, as a share of one core, and its threads.
//!
//! `cargo bench -p vos-node --bench agents` (after `just build-agent
//! build-test-actors`). Data goes under `target/`: on the reference laptop
//! `/tmp` is tmpfs.

use std::sync::Arc;
use std::time::{Duration, Instant};

use vos_node::{CallError, Config, Node, Peers, Reply, Space, SpaceNode};
use vos_wire::Encode;
use vos_wire::batch::Request;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, Session};
use vos_wire::peer::NodeNumber;
use vos_wire::result::Outcome;
use vos_wire::schema::Schema;

const COUNTER: InstanceId = InstanceId(1);
const NODES: u8 = 3;
const WARM: Duration = Duration::from_secs(2);
const MEASURE: Duration = Duration::from_secs(5);
const IDLE_SETTLE: Duration = Duration::from_secs(5);
const IDLE_MEASURE: Duration = Duration::from_secs(10);

fn elf(path: &str) -> Vec<u8> {
    let path = format!("{}/../../agent/{path}", env!("CARGO_MANIFEST_DIR"));
    let elf = std::fs::read(&path).unwrap_or_else(|error| {
        panic!("{path}: {error}; run `just build-agent build-test-actors`")
    });
    vos_pvm_compiler::link_elf_spi(&elf).expect("links")
}

fn method(program: &[u8], name: &str) -> MethodId {
    let parsed = vos_pvm::spi::parse_standard_program(program).unwrap();
    Schema::read(&parsed.ro_data)
        .unwrap()
        .methods
        .iter()
        .find(|method| method.name == name.as_bytes())
        .unwrap()
        .id
}

fn count(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(default)
}

/// Three nodes of one space over QUIC.
fn nodes(agent: &[u8], root: &std::path::Path) -> Vec<Arc<Node>> {
    let dirs: Vec<_> = (1..=NODES)
        .map(|number| root.join(format!("node-{number}")))
        .collect();
    let members: Vec<SpaceNode> = dirs
        .iter()
        .zip(1..)
        .map(|(dir, number)| {
            // A first open makes each node's key.
            let node = Node::open(dir, Config::new(agent.to_vec())).unwrap();
            let key = node.id().0;
            node.shutdown();
            let peer = std::net::UdpSocket::bind("127.0.0.1:0")
                .unwrap()
                .local_addr()
                .unwrap();
            SpaceNode {
                number,
                key,
                peer,
                ingress: format!("http://node-{number}"),
            }
        })
        .collect();
    let space = Space::new(members).unwrap();
    dirs.iter()
        .map(|dir| {
            let mut config = Config::new(agent.to_vec());
            config.space = Some(space.clone());
            config.peers = Peers::Quic;
            Arc::new(Node::open(dir, config).unwrap())
        })
        .collect()
}

fn leader(nodes: &[Arc<Node>], agent: AgentId) -> NodeNumber {
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        if let Some(index) = nodes.iter().position(|node| node.leads(agent)) {
            return index as NodeNumber + 1;
        }
        assert!(Instant::now() < until, "no leader for agent {}", agent.0);
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn create(nodes: &[Arc<Node>]) -> AgentId {
    loop {
        match nodes[0].create_replicated(vec![1, 2, 3]) {
            Ok(agent) => return agent,
            Err(CallError::Unconfirmed(agent)) => return agent,
            Err(error) => {
                eprintln!("creation: {error:?}");
                std::thread::sleep(Duration::from_millis(50));
            }
        }
    }
}

/// The process's CPU time so far: user and system, in clock ticks.
fn cpu_ticks() -> u64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap();
    // The command may hold spaces: fields count from after its `)`.
    let fields: Vec<&str> = stat[stat.rfind(')').unwrap() + 2..].split(' ').collect();
    fields[11].parse::<u64>().unwrap() + fields[12].parse::<u64>().unwrap()
}

fn threads() -> usize {
    std::fs::read_dir("/proc/self/task").unwrap().count()
}

/// The median and the 99th percentile, by nearest rank, in milliseconds.
fn percentiles(mut samples: Vec<Duration>) -> (f64, f64) {
    samples.sort();
    let at = |fraction: f64| {
        let rank = (samples.len() as f64 * fraction).ceil() as usize;
        samples[rank.max(1) - 1].as_secs_f64() * 1e3
    };
    (at(0.5), at(0.99))
}

/// One session's closed loop on `agent` until `until`: its calls'
/// latencies from `measure_from` on.
async fn session(
    nodes: Arc<Vec<Arc<Node>>>,
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
        match nodes[usize::from(at) - 1].call(agent, request).await {
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

fn main() {
    let agents = count("AGENTS", 64);
    let sessions = count("SESSIONS", 4);
    let idle = count("IDLE", 1_000);
    let agent_program = elf("default/target/riscv64em-vos/release/vos-agent.elf");
    let counter = elf("test-actors/target/riscv64em-vos/release/counter.elf");
    let increment = method(&counter, "increment");
    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let nodes = Arc::new(nodes(&agent_program, dir.path()));

    let started = Instant::now();
    let active: Vec<AgentId> = (0..agents).map(|_| create(&nodes)).collect();
    for &agent in &active {
        let at = leader(&nodes, agent);
        let installed = smol::block_on(nodes[usize::from(at) - 1].install(
            agent,
            COUNTER,
            &counter,
            &[],
            vec![],
        ));
        assert!(
            matches!(installed, Ok(Reply::Ran(Outcome::Done(_)))),
            "{installed:?}"
        );
    }
    let mut leading = [0; NODES as usize];
    for &agent in &active {
        leading[usize::from(leader(&nodes, agent)) - 1] += 1;
    }
    println!(
        "{agents} agents created and installed in {:.1} s; leaders per node {leading:?}",
        started.elapsed().as_secs_f64()
    );

    let measure_from = Instant::now() + WARM;
    let until = measure_from + MEASURE;
    let cpu = std::thread::spawn(move || {
        std::thread::sleep(measure_from.saturating_duration_since(Instant::now()));
        let ticks = cpu_ticks();
        std::thread::sleep(MEASURE);
        (cpu_ticks() - ticks) as f64 / 100.0 / MEASURE.as_secs_f64()
    });
    let latencies: Vec<Duration> = smol::block_on(async {
        let tasks: Vec<_> = active
            .iter()
            .flat_map(|&agent| (0..sessions).map(move |number| (agent, number)))
            .map(|(agent, number)| {
                smol::spawn(session(
                    Arc::clone(&nodes),
                    agent,
                    number,
                    increment,
                    measure_from,
                    until,
                ))
            })
            .collect();
        let mut all = Vec::new();
        for task in tasks {
            all.extend(task.await);
        }
        all
    });
    let commits = latencies.len();
    let (p50, p99) = percentiles(latencies);
    println!(
        "active: {agents} agents × {sessions} sessions: {:.0} commits per second, p50 {p50:.2} ms, p99 {p99:.2} ms, {:.0}% of one core",
        commits as f64 / MEASURE.as_secs_f64(),
        cpu.join().unwrap() * 100.0
    );

    let started = Instant::now();
    for _ in 0..idle {
        create(&nodes);
    }
    println!(
        "{idle} idle agents created in {:.1} s",
        started.elapsed().as_secs_f64()
    );
    std::thread::sleep(IDLE_SETTLE);
    let ticks = cpu_ticks();
    let measured = Instant::now();
    std::thread::sleep(IDLE_MEASURE);
    let share = (cpu_ticks() - ticks) as f64 / 100.0 / measured.elapsed().as_secs_f64();
    println!(
        "idle: {} groups per node, {:.1}% of one core for three nodes, {} threads",
        agents + idle,
        share * 100.0,
        threads()
    );
    for node in Arc::into_inner(nodes).expect("tasks done") {
        Arc::into_inner(node).expect("one owner").shutdown();
    }
}
