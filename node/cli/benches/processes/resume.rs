//! A workflow's resume on three nodes: a reply delivered to the workflow's
//! leader, until its next step is applied there, as the one-node
//! acceptance bench (`vos-node`'s `acceptance`) times it. Node 1, the
//! leader, runs in this process on its share of the cores, so the bench
//! delivers the replies of an agent no node holds as that agent's would
//! arrive; nodes 2 and 3 are `vos node run` processes over QUIC. Each tour
//! of the rounds actor awaits a reply each round, at an agent on the three
//! nodes and, in turn, at one on node 1 alone: the difference is the
//! replication's.

use std::time::{Duration, Instant};

use vos_checker::calls::installed;
use vos_checker::percentiles;
use vos_checker::processes::{Running, space_file};
use vos_checker::programs;
use vos_checker::rounds::{ROUNDS, Rounds, Tour};
use vos_checker::spaces::{free_tcp_port, free_udp_port};
use vos_node::{Config, Node, Reply, Space};
use vos_wire::batch::{Answer, Await, Body, Message, Request};
use vos_wire::ids::{AgentId, Principal, Session, WorkflowId};
use vos_wire::ingress::Stats;
use vos_wire::records::{Workflow, WorkflowState};
use vos_wire::result::Outcome;
use vos_wire::{Encode, keys};

use crate::NODES;
use crate::nodes::{data_dir, launch, pin_thread};

/// Tours of each kind, taken in turn, each on an agent of its own.
const TOURS: u8 = 3;
/// A tour's rounds: each a resume.
const ROUNDS_A_TOUR: u64 = 201;
/// The agent a tour asks, which no node holds: the bench delivers its
/// replies.
const ASKED: AgentId = AgentId(0x0a5c);
/// The leader's stages reported, their means over each kind's tours.
const STAGES: [&str; 9] = [
    "queued",
    "prepare",
    "refine",
    "dry_run",
    "propose",
    "commit",
    "apply",
    "dispatch",
    "flush_synced",
];

/// Each stage's sum and count over some windows of a node's stats.
#[derive(Default)]
struct Sums(Vec<(String, u64, u64)>);

impl Sums {
    /// Add each stage's sum and count between `before` and `after`.
    fn add(&mut self, before: &Stats, after: &Stats) {
        for stage in &after.stages {
            let Some(earlier) = before.stages.iter().find(|e| e.name == stage.name) else {
                continue;
            };
            let count = stage.counts.iter().sum::<u64>() - earlier.counts.iter().sum::<u64>();
            let total = stage.total - earlier.total;
            match self.0.iter_mut().find(|(name, ..)| *name == stage.name) {
                Some((_, sum, counted)) => {
                    *sum += total;
                    *counted += count;
                }
                None => self.0.push((stage.name.clone(), total, count)),
            }
        }
    }

    /// The mean of `stage`, and its count.
    fn mean(&self, stage: &str) -> (f64, u64) {
        self.0
            .iter()
            .find(|(name, ..)| name == stage)
            .map_or((0.0, 0), |(_, sum, count)| {
                (*sum as f64 / (*count).max(1) as f64, *count)
            })
    }
}

/// One kind of tour: its agents' replicas, its resumes and the leader's
/// stages over them.
struct Kind {
    name: &'static str,
    replicas: Vec<u8>,
    samples: Vec<Duration>,
    sums: Sums,
}

pub fn measure(cpus: &[String], pinned: bool) {
    let dir = data_dir();
    let program = programs::agent();
    let data = |number: usize| dir.path().join(format!("node-{number}"));
    let log = |number: usize| dir.path().join(format!("node-{number}.log"));
    // Node 1's key, from a first open of its directory; the others' from
    // a first run of each.
    let first = Node::open(data(1), Config::new(program.clone())).unwrap();
    let mut keys = vec![hex::encode(first.id().0)];
    first.shutdown();
    keys.extend((2..=NODES).map(|number| {
        vos_checker::processes::first_run(&crate::nodes::vos(), &data(number), &log(number))
    }));
    let ingress: Vec<u16> = (0..NODES).map(|_| free_tcp_port()).collect();
    let peers: Vec<u16> = (0..NODES).map(|_| free_udp_port()).collect();
    let urls: Vec<String> = ingress
        .iter()
        .map(|port| format!("http://127.0.0.1:{port}"))
        .collect();
    let space_path = dir.path().join("space");
    let listed = (0..NODES).map(|at| {
        let peer = std::net::SocketAddr::from(([127, 0, 0, 1], peers[at]));
        (&*keys[at], peer, &*urls[at])
    });
    std::fs::write(&space_path, space_file(listed)).unwrap();
    let _followers: Vec<Running> = (2..=NODES)
        .map(|number| {
            let listen = format!("127.0.0.1:{}", ingress[number - 1]);
            let data = data(number);
            let args = [
                "--data",
                data.to_str().unwrap(),
                "--listen",
                &listen,
                "--space",
                space_path.to_str().unwrap(),
            ];
            let cpus = pinned.then(|| cpus[number - 1].as_str());
            launch(&args, cpus, &log(number)).0
        })
        .collect();
    // Opened on a thread on node 1's cores, so every thread the node
    // starts runs there, and its executors are as many as a process
    // there has.
    let node = std::thread::scope(|scope| {
        scope
            .spawn(|| {
                if pinned {
                    pin_thread(&cpus[0]);
                }
                let mut config = Config::new(program);
                config.space = Some(Space::read(&space_path).unwrap());
                let node = Node::open(data(1), config).unwrap();
                node.serve(format!("127.0.0.1:{}", ingress[0]).parse().unwrap())
                    .unwrap();
                node
            })
            .join()
            .unwrap()
    });
    let rounds = Rounds::load();
    let mut kinds = [
        Kind {
            name: "three replicas",
            replicas: vec![1, 2, 3],
            samples: Vec::new(),
            sums: Sums::default(),
        },
        Kind {
            name: "node 1 alone",
            replicas: Vec::new(),
            samples: Vec::new(),
            sums: Sums::default(),
        },
    ];
    // In turn, so a change in the machine's load meets both kinds.
    for tour in 0..TOURS {
        for kind in &mut kinds {
            let agent = touring(&node, &kind.replicas, &rounds);
            let before = node.stats();
            kind.samples.extend(resumes(&node, agent, &rounds, tour));
            kind.sums.add(&before, &node.stats());
        }
    }
    for kind in kinds {
        let count = kind.samples.len();
        let (median, p99) = percentiles(kind.samples, Duration::from_micros(1));
        let stages: Vec<String> = STAGES
            .iter()
            .map(|stage| {
                let (mean, count) = kind.sums.mean(stage);
                format!("{stage} {mean:.0} ({count})")
            })
            .collect();
        println!(
            "a workflow's resume, {}: a reply delivered to its next step applied, {count} resumes: median {median:.0} µs, p99 {p99:.0} µs",
            kind.name
        );
        println!("  the leader's stages, mean µs: {}", stages.join(", "));
    }
    node.shutdown();
}

/// An agent on `replicas` (node 1 alone when none) that node 1 leads,
/// with the rounds installed.
fn touring(node: &Node, replicas: &[u8], rounds: &Rounds) -> AgentId {
    for _ in 0..30 {
        let agent = node.create_replicated(replicas.to_vec()).unwrap();
        let until = Instant::now() + Duration::from_secs(30);
        let leads = loop {
            match node.replica(agent) {
                Some(status) if status.leads => break true,
                Some(status) if status.leader.is_some() => break false,
                _ => {}
            }
            assert!(Instant::now() < until, "agent {} has no leader", agent.0);
            std::thread::sleep(Duration::from_millis(10));
        };
        if leads {
            installed(smol::block_on(node.install(
                agent,
                ROUNDS,
                &rounds.elf,
                vec![],
            )));
            return agent;
        }
    }
    panic!("node 1 led none of 30 new agents");
}

/// Workflow `id`'s state, as `node` applied it.
fn state(node: &Node, agent: AgentId, id: WorkflowId) -> WorkflowState {
    vos_checker::applied::<Workflow>(node.store(), agent, &keys::workflow(id))
        .expect("the workflow's record")
        .state
}

/// A tour's resumes at `agent`, in a session numbered `session`: each the
/// time from a reply delivered to node 1, the tour's leader, until the
/// tour's next step is applied there.
fn resumes(node: &Node, agent: AgentId, rounds: &Rounds, session: u8) -> Vec<Duration> {
    let key = [session + 1; 32];
    let tour = Tour::light(ASKED, (1..=ROUNDS_A_TOUR).collect(), 0);
    let start = Request {
        session: Session {
            key,
            name: [session + 1; 16],
            t0: vos_node::wall_clock(),
        },
        sequence: 1,
        caller: Principal::Client(key),
        instance: ROUNDS,
        method: rounds.methods.tour,
        arguments: tour.arguments(),
    };
    let id = match smol::block_on(node.call(agent, start)) {
        Ok(Reply::Ran(Outcome::Started(id))) => id,
        other => panic!("{other:?}"),
    };
    let awaiting = || loop {
        match state(node, agent, id) {
            WorkflowState::Awaiting { counter, .. } => return Some(counter),
            WorkflowState::Ended(_) => return None,
            _ => std::thread::yield_now(),
        }
    };
    let mut total = 0;
    let mut samples = Vec::new();
    while let Some(counter) = awaiting() {
        let sequence = samples.len() as u64 + 1;
        total += sequence;
        let reply = Message {
            from: ASKED,
            sequence,
            body: Body::Reply {
                awaiting: Await {
                    workflow: id,
                    counter,
                },
                answer: Answer::Done(total.encode()),
            },
        };
        let started = Instant::now();
        node.deliver(agent, reply).unwrap();
        while matches!(
            state(node, agent, id),
            WorkflowState::Awaiting { counter: at, .. } if at == counter
        ) {
            std::thread::yield_now();
        }
        samples.push(started.elapsed());
    }
    assert_eq!(samples.len() as u64, ROUNDS_A_TOUR, "a resume a round");
    samples
}
