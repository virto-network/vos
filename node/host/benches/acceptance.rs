//! A node's costs with storage: the default agent with the counter
//! installed, driven through the node's own API.
//! - Per request under load: increments from many sessions at once, one in
//!   flight per session, so batches fill. Wall time per applied request
//!   covers refine, accumulate and the durable commit, shared by a batch;
//!   hooks split it into execution (from refine's start to the commit's)
//!   and the commits.
//! - One request alone: its latency, the batch's linger and its commit's
//!   sync included, and its execution alone.
//! - A query: the counter's `value` on applied state.
//! - A workflow's resume: a reply delivered to the leader, until the
//!   workflow's next step is applied. A tour of the rounds actor awaits an
//!   agent the node does not hold, whose replies the bench delivers as
//!   that agent's would arrive; each resumed step runs its round and
//!   awaits the next reply.
//!
//! `cargo bench -p vos-node --bench acceptance` (after `just build-agent
//! build-test-actors`); `GREY_PVM=interpreter` runs the interpreter. Data
//! goes under `target/`: on the reference laptop `/tmp` is tmpfs.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vos_checker::calls::done;
use vos_checker::percentiles;
use vos_checker::programs::{Programs, method};
use vos_checker::workflows::{ROUNDS, Rounds, Tour};
use vos_node::{Config, Hooks, Node, Reply};
use vos_wire::batch::{Answer, Await, Batch, Body, Message, Request};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, Session, WorkflowId};
use vos_wire::ingress::Stats;
use vos_wire::records::{Workflow, WorkflowState, unstored};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, keys};

const COUNTER: InstanceId = InstanceId(1);
const ALICE: Principal = Principal::Client([1; 32]);
const SESSIONS: u64 = 256;
const PER_SESSION: u64 = 100;
const ALONE: usize = 201;
const QUERIES: usize = 2001;
const RESUMES: u64 = 201;
/// The agent a tour asks, which the node does not hold: the bench delivers
/// its replies.
const ASKED: AgentId = AgentId(0x0a5c);

fn increment(session: u64, sequence: u64, method: MethodId) -> Request {
    request(session, sequence, COUNTER, method, 1u64.encode())
}

/// A request of `method` at `instance` in `session`.
fn request(
    session: u64,
    sequence: u64,
    instance: InstanceId,
    method: MethodId,
    arguments: Vec<u8>,
) -> Request {
    // Every session starts when the bench does, each with a key of its
    // own: one key's sessions are capped.
    static START: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    let mut key = [1; 32];
    key[..8].copy_from_slice(&session.to_be_bytes());
    Request {
        session: Session {
            key,
            name: u128::from(session).to_be_bytes(),
            t0: *START.get_or_init(vos_node::wall_clock),
        },
        sequence,
        caller: Principal::Client(key),
        instance,
        method,
        arguments,
    }
}

/// Workflow `id`'s state, as `node` applied it.
fn state(node: &Node, agent: AgentId, id: WorkflowId) -> WorkflowState {
    let bytes = node
        .store()
        .snapshot()
        .get(agent, &keys::workflow(id))
        .unwrap()
        .expect("the workflow's record");
    Workflow::decode(unstored(&bytes).unwrap()).unwrap().0.state
}

/// A tour's resumes at `agent`, which runs the rounds actor: each the time
/// from a reply delivered to the node, the tour's leader, until the tour's
/// next step is applied.
fn resumes(node: &Node, agent: AgentId, session: u64) -> Vec<Duration> {
    let rounds = Rounds::load();
    let methods = rounds.methods;
    let install = node.install(agent, ROUNDS, &rounds.elf, vec![]);
    let installed = smol::block_on(install);
    assert!(
        matches!(installed, Ok(Reply::Ran(Outcome::Done(_)))),
        "{installed:?}"
    );
    let tour = Tour {
        other: ASKED,
        amounts: (1..=RESUMES).collect(),
        nap: 0,
        words: 64,
        passes: 4,
    };
    let start = request(session, 1, ROUNDS, methods.tour, tour.arguments());
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
        total += samples.len() as u64 + 1;
        let reply = Message {
            from: ASKED,
            sequence: samples.len() as u64 + 1,
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
    assert_eq!(samples.len() as u64, RESUMES, "a resume a round");
    samples
}

/// Run `per_session` increments in each of `sessions`, starting at session
/// `first`, all sessions at once: the wall time.
fn load(
    node: &Arc<Node>,
    agent: AgentId,
    increment_method: MethodId,
    first: u64,
    sessions: u64,
    per_session: u64,
) -> Duration {
    let started = Instant::now();
    smol::block_on(async {
        let tasks: Vec<_> = (first..first + sessions)
            .map(|session| {
                let node = Arc::clone(node);
                smol::spawn(async move {
                    for sequence in 1..=per_session {
                        let request = increment(session, sequence, increment_method);
                        done(node.call(agent, request).await);
                    }
                })
            })
            .collect();
        for task in tasks {
            task.await;
        }
    });
    started.elapsed()
}

/// Where batches spend their time: from refine's start to the commit's
/// start (refine, accumulate and the hops between threads), and the
/// commits.
#[derive(Default)]
struct Phases {
    started: Option<Instant>,
    committing: Option<Instant>,
    execution: Duration,
    commits: Duration,
    batches: u64,
    inputs: u64,
}

#[derive(Default)]
struct Timing(Mutex<Phases>);

impl Timing {
    fn take(&self) -> Phases {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

impl Hooks for Timing {
    fn fail_refine(&self, _: AgentId, batch: &Batch) -> bool {
        let mut phases = self.0.lock().unwrap();
        phases.started = Some(Instant::now());
        phases.inputs += batch.inputs.len() as u64;
        false
    }

    fn before_commit(&self) {
        let mut phases = self.0.lock().unwrap();
        if let Some(started) = phases.started.take() {
            phases.execution += started.elapsed();
            phases.committing = Some(Instant::now());
        }
    }

    fn after_commit(&self, _: AgentId, _: u64) -> bool {
        let mut phases = self.0.lock().unwrap();
        if let Some(committing) = phases.committing.take() {
            phases.commits += committing.elapsed();
            phases.batches += 1;
        }
        true
    }
}

/// Each stage's mean between two of the node's stats: its values' sum
/// over their count.
fn stage_means(before: &Stats, after: &Stats) -> Vec<(String, f64)> {
    after
        .stages
        .iter()
        .filter_map(|stage| {
            let earlier = before
                .stages
                .iter()
                .find(|earlier| earlier.name == stage.name)?;
            let count = stage
                .counts
                .iter()
                .sum::<u64>()
                .saturating_sub(earlier.counts.iter().sum::<u64>());
            let total = stage.total.saturating_sub(earlier.total);
            (count > 0).then(|| (stage.name.clone(), total as f64 / count as f64))
        })
        .collect()
}

fn main() {
    let Programs {
        agent: agent_program,
        counter,
        counter_elf,
    } = Programs::load();
    let increment_method = method(&counter, "increment");
    let value = method(&counter, "value");
    let backend = std::env::var("GREY_PVM").unwrap_or_else(|_| "default".into());

    let dir = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    let timing = Arc::new(Timing::default());
    let mut config = Config::new(agent_program);
    config.hooks = Arc::clone(&timing) as Arc<dyn Hooks>;
    let executors = config.executors;
    let node = Arc::new(Node::open(dir.path(), config).unwrap());
    let agent = node.create_agent().unwrap();
    let installed = smol::block_on(node.install(agent, COUNTER, &counter_elf, vec![]));
    assert!(
        matches!(installed, Ok(Reply::Ran(Outcome::Done(_)))),
        "{installed:?}"
    );

    // Warm the machines, the store and the queues once.
    load(&node, agent, increment_method, 1, SESSIONS, 10);
    timing.take();
    let before = node.stats();
    let elapsed = load(
        &node,
        agent,
        increment_method,
        SESSIONS + 1,
        SESSIONS,
        PER_SESSION,
    );
    let requests = SESSIONS * PER_SESSION;
    let per_request = elapsed.as_secs_f64() * 1e6 / requests as f64;
    let phases = timing.take();
    assert_eq!(phases.inputs, requests, "every request ran once");
    let stages = stage_means(&before, &node.stats());

    let alone_session = 2 * SESSIONS + 1;
    let alone: Vec<Duration> = (1..=ALONE as u64)
        .map(|sequence| {
            let started = Instant::now();
            done(smol::block_on(node.call(
                agent,
                increment(alone_session, sequence, increment_method),
            )));
            started.elapsed()
        })
        .collect();
    assert!(!alone.is_empty(), "a request alone was timed");
    let (alone_median, alone_p99) = percentiles(alone, Duration::from_micros(1));
    let alone_phases = timing.take();
    assert_eq!(alone_phases.inputs, ALONE as u64, "one request per batch");

    let queries: Vec<Duration> = (0..QUERIES)
        .map(|_| {
            let started = Instant::now();
            let outcome =
                smol::block_on(node.query(agent, ALICE, COUNTER, value, Vec::new())).unwrap();
            assert!(matches!(outcome, Outcome::Done(_)), "{outcome:?}");
            started.elapsed()
        })
        .collect();
    assert!(!queries.is_empty(), "a query was timed");
    let (query_median, query_p99) = percentiles(queries, Duration::from_micros(1));

    println!("backend {backend}, {executors} executors");
    println!(
        "under load: {requests} increments from {SESSIONS} sessions in {:.2} s: {per_request:.1} µs per request ({:.0} per second)",
        elapsed.as_secs_f64(),
        requests as f64 / elapsed.as_secs_f64(),
    );
    println!(
        "  of which execution {:.1} µs per request; {} batches of {:.0} requests on average, {:.2} ms per commit",
        phases.execution.as_secs_f64() * 1e6 / phases.inputs as f64,
        phases.batches,
        phases.inputs as f64 / phases.batches as f64,
        phases.commits.as_secs_f64() * 1e3 / phases.batches as f64,
    );
    let mean = |name: &str| {
        stages
            .iter()
            .find(|(stage, _)| stage == name)
            .map_or(0.0, |(_, mean)| *mean)
    };
    println!(
        "  the stages' means: {} inputs a batch; refine {:.0} µs ({:.1} µs an input), the dry run {:.0} µs ({:.1} µs an input)",
        mean("batch_inputs"),
        mean("refine"),
        mean("refine") / mean("batch_inputs"),
        mean("dry_run"),
        mean("dry_run") / mean("batch_inputs"),
    );
    println!(
        "one request alone: median {alone_median:.0} µs, p99 {alone_p99:.0} µs; execution {:.1} µs on average",
        alone_phases.execution.as_secs_f64() * 1e6 / ALONE as f64,
    );
    println!("query: median {query_median:.1} µs, p99 {query_p99:.1} µs");

    timing.take();
    let resumed = resumes(&node, agent, alone_session + 1);
    let resume_phases = timing.take();
    let (resume_median, resume_p99) = percentiles(resumed, Duration::from_micros(1));
    println!(
        "a workflow's resume, a reply delivered to its next step applied: median {resume_median:.0} µs, p99 {resume_p99:.0} µs; execution {:.1} µs a batch on average",
        resume_phases.execution.as_secs_f64() * 1e6 / resume_phases.batches.max(1) as f64,
    );
    Arc::into_inner(node).expect("tasks done").shutdown();
}
