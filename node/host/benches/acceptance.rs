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
//!
//! `cargo bench -p vos-node --bench acceptance` (after `just build-agent
//! build-test-actors`); `GREY_PVM=interpreter` runs the interpreter. Data
//! goes under `target/`: on the reference laptop `/tmp` is tmpfs.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vos_node::{CallError, Config, Hooks, Node, Reply};
use vos_wire::batch::{Batch, Request};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, Session};
use vos_wire::ingress::Stats;
use vos_wire::result::Outcome;
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode};

const COUNTER: InstanceId = InstanceId(1);
const ALICE: Principal = Principal::Client([1; 32]);
const SESSIONS: u64 = 256;
const PER_SESSION: u64 = 100;
const ALONE: usize = 201;
const QUERIES: usize = 2001;

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

fn increment(session: u64, sequence: u64, method: MethodId) -> Request {
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
        instance: COUNTER,
        method,
        arguments: 1u64.encode(),
    }
}

fn done(reply: Result<Reply, CallError>) -> u64 {
    match reply {
        Ok(Reply::Ran(Outcome::Done(bytes))) => u64::decode(&bytes).unwrap().0,
        other => panic!("not done: {other:?}"),
    }
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

/// The median and the 99th percentile, by nearest rank, in microseconds.
fn percentiles(mut samples: Vec<Duration>) -> (f64, f64) {
    samples.sort();
    let at = |fraction: f64| {
        let rank = (samples.len() as f64 * fraction).ceil() as usize;
        samples[rank.max(1) - 1].as_secs_f64() * 1e6
    };
    (at(0.5), at(0.99))
}

fn main() {
    let agent_program = elf("default/target/riscv64em-vos/release/vos-agent.elf");
    let counter = elf("test-actors/target/riscv64em-vos/release/counter.elf");
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
    let installed = smol::block_on(node.install(agent, COUNTER, &counter, &[], vec![]));
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
    let (alone_median, alone_p99) = percentiles(alone);
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
    let (query_median, query_p99) = percentiles(queries);

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
    Arc::into_inner(node).expect("tasks done").shutdown();
}
