//! The executors' bound (slice 7's 7.11 gate, S44 as S55 states it): a
//! node of `k` executor threads, its verification budget their default
//! `2k`, takes at least `100·k` credentialed calls a second, each an owner
//! proof's transfer verified at its ingress, and their 99th percentile
//! latency is within 50 ms of signed calls' at the same rate, for `k` up to
//! the host's physical performance cores. No absolute rate is claimed.
//!
//! One node of a founded space of one runs `AGENTS` agents of the purses'
//! ledger and the counter. For each run the proofs are made first, on
//! every core of the generator, enough for `--seconds` (10 by default) at
//! `100·k` a second, each good until 115 s past when making them all is
//! expected to end (a proof expires at most 120 s after the node's time),
//! the run waiting for that moment if they were made sooner; then they are
//! sent open loop at `100·k` a second by `SENDERS` threads, the latency of
//! each from the time it was due; then signed increments at the same rate,
//! the same way. `SENDERS` bounds the calls in flight, so the generator
//! sends at most `SENDERS / latency` a second: a run reports its calls in
//! flight, the mean and the most, to show it was not the bound. The node's
//! stats give each verification's wait for an executor and its run, so a
//! miss says whether it was the verification or the queue.
//!
//! Three modes:
//! - `cargo bench -p vos-node --bench credentialed -- [--seconds S] k…`:
//!   for each `k` (1, 2, 4 … up to the host's `N`, and `N`, if none), the
//!   node and the generator in this process, over the node API's socket;
//! - `… -- serve --listen ADDRESS [--executors k]`: the node alone, its
//!   executors the cores it may run on unless given (start it under
//!   `taskset -c CORES` to pin it), served over QUIC on `ADDRESS`; it
//!   prints the `drive` arguments that reach it and serves until its input
//!   ends;
//! - `… -- drive --node quic://HOST:PORT --key HEX --space HEX --agents
//!   A,B,… [--seconds S] k`: the generator alone, from another host, at
//!   `100·k` a second over QUIC.
//!
//! After `just build-agent build-test-actors`.

use std::io::BufRead;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use rayon::prelude::*;
use vos_checker::calls::installed;
use vos_checker::programs::{Programs, actor, method, package};
use vos_node::client::{self, Client, Operator, Target};
use vos_node::{Config, Node};
use vos_pvm_final_verifier::credential as verifier;
use vos_pvm_recair::credential::{OwnerPublic, Statement, prove};
use vos_pvm_recair::masked::MaskRng;
use vos_wire::credentials::{self as tree, Bound, Tag, Words};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal};
use vos_wire::ingress::{CredentialPublic, Credentialed, Response, Stage};
use vos_wire::result::Outcome;
use vos_wire::{Encode, SpaceId, WindowClock};

const PURSES: InstanceId = InstanceId(2);
const COUNTER: InstanceId = InstanceId(1);
const AGENTS: usize = 4;
/// A run's length unless `--seconds` says otherwise.
const SECONDS: f64 = 10.0;
/// Calls in flight at once, at most: the senders.
const SENDERS: usize = 96;
/// The operator's key, which the node lists: its roles, and its stats.
const OPERATOR: [u8; 32] = [21; 32];
/// The generator's QUIC client key, which a served node lists.
const DRIVER: [u8; 32] = [22; 32];
/// The payer's secret, whose owner digest owns both rows.
const SECRET: Words = [77, 78, 79, 80, 81, 82, 83, 84];
/// How long a proof may live past the node's time when it is sent: a
/// margin under the node's horizon (120 s).
const LIFE_MS: u64 = 115_000;

/// One node of a founded space, its agents ready: each with a row
/// `payer`, owned by the secret's owner digest and full, and `payee`.
struct Served {
    node: Node,
    socket: Target,
    space: SpaceId,
    agents: Vec<AgentId>,
    _dir: tempfile::TempDir,
}

fn owner() -> Words {
    tree::compress(&Tag::Owner.block(), &SECRET)
}

fn start(executors: usize) -> Served {
    let programs = Programs::load();
    let dir = tempfile::tempdir_in(std::env::temp_dir()).unwrap();
    let ingress = format!("http://127.0.0.1:{}", vos_checker::spaces::free_tcp_port());
    let space = vos_checker::spaces::space(&programs.agent, &[dir.path()], |_| ingress.clone());
    let genesis = space
        .found(WindowClock::DEFAULT, vos_node::wall_clock(), [3; 16])
        .unwrap();
    let space = space.with_genesis(genesis).unwrap();
    let id = space.id();
    let key = SigningKey::from_bytes(&OPERATOR);
    let operator_key = key.verifying_key().to_bytes();
    let node = vos_checker::spaces::open_node(1, dir.path(), || {
        let mut config = Config::new(programs.agent.clone());
        config.executors = executors;
        config.space = Some(space.clone());
        config.operators = vec![operator_key];
        config
    });
    let path = dir.path().join("api.sock");
    node.serve_socket(&path, 0o600).unwrap();
    let socket = Target::socket(path);
    let owner = tree::digest(&owner());
    let operator = Principal::Client(operator_key);
    let mut client = Client::new(&socket, key);
    let purses = actor("purses");
    let mut agents = Vec::new();
    for _ in 0..AGENTS {
        let agent = node.create_agent().unwrap();
        let roles = vec![(b"operator".to_vec(), 1)];
        installed(smol::block_on(node.install(
            agent,
            PURSES,
            &package("purses"),
            roles,
        )));
        installed(smol::block_on(node.install(
            agent,
            COUNTER,
            &package("counter"),
            Vec::new(),
        )));
        installed(smol::block_on(node.set_role(agent, operator, Some(1))));
        let expires = vos_node::wall_clock() + 60_000;
        for (name, amount) in [("payer", u64::MAX / 2), ("payee", 0)] {
            let name = name.as_bytes().to_vec();
            for (method_name, arguments) in [
                ("invite_row", (name.clone(), owner, expires).encode()),
                ("claim_row", (name.clone(), owner).encode()),
                ("mint", (name.clone(), amount).encode()),
            ] {
                let answer = client
                    .call(agent, PURSES, method(&purses, method_name), &arguments)
                    .unwrap();
                assert!(ran(&answer), "{method_name}: {answer:?}");
            }
        }
        agents.push(agent);
    }
    Served {
        node,
        socket,
        space: id,
        agents,
        _dir: dir,
    }
}

fn ran(answer: &Response) -> bool {
    matches!(
        answer,
        Response::Ran {
            outcome: Outcome::Done(_),
            ..
        }
    )
}

/// A node as the generator reaches it.
struct Reached {
    target: Target,
    space: SpaceId,
    agents: Vec<AgentId>,
}

impl Reached {
    /// Transfers enough for `seconds` at `rate`, each proved by the
    /// payer's owner, round the agents, good until `LIFE_MS` past when
    /// making them is expected to end, at the rate a first round of four
    /// on every core makes them; returned at that moment by the node's
    /// clock, or once made if later.
    fn calls(&self, rate: f64, seconds: f64) -> Vec<(AgentId, Credentialed)> {
        let round = 4 * rayon::current_num_threads();
        let started = Instant::now();
        let now = client::time(&self.target).unwrap();
        self.made(round, now + LIFE_MS);
        let per_second = round as f64 / started.elapsed().as_secs_f64();
        let count = (rate * seconds).ceil() as usize;
        let expected = (count as f64 / per_second * 1.1 * 1e3) as u64 + 5_000;
        let ready = client::time(&self.target).unwrap() + expected;
        let calls = self.made(count, ready + LIFE_MS);
        let now = client::time(&self.target).unwrap();
        if now < ready {
            std::thread::sleep(Duration::from_millis(ready - now));
        }
        let now = client::time(&self.target).unwrap();
        assert!(
            now + (seconds * 1e3) as u64 + 10_000 <= ready + LIFE_MS,
            "the proofs took {} s longer than expected to make",
            (now - ready) / 1_000
        );
        calls
    }

    fn made(&self, count: usize, expires_ms: u64) -> Vec<(AgentId, Credentialed)> {
        let transfer = method(&actor("purses"), "transfer");
        let arguments = (b"payer".to_vec(), b"payee".to_vec(), 1u64).encode();
        let owner = owner();
        (0..count)
            .into_par_iter()
            .map(|index| {
                let agent = self.agents[index % self.agents.len()];
                let mut nonce = [0u8; 16];
                nonce[..8].copy_from_slice(&(index as u64).to_le_bytes());
                nonce[8..].copy_from_slice(&expires_ms.to_le_bytes());
                let b = Bound {
                    space: &self.space,
                    agent,
                    instance: PURSES,
                    method: transfer,
                    program: verifier::program(verifier::CredentialKind::Owner),
                    kind: 1,
                    arguments: &arguments,
                    nonce: &nonce,
                    expires_ms,
                }
                .digest();
                let binding = tree::binding(&b);
                let statement = Statement::Owner(
                    OwnerPublic {
                        owner,
                        binding: tree::words(&binding).unwrap(),
                    },
                    SECRET,
                );
                let (proof, _) = prove(&statement, MaskRng::default()).expect("proves");
                let call = Credentialed {
                    instance: PURSES,
                    method: transfer,
                    arguments: arguments.clone(),
                    nonce,
                    expires_ms,
                    format: verifier::FORMAT,
                    public: CredentialPublic::Owner {
                        owner: tree::digest(&owner),
                        binding,
                    },
                    proof: verifier::encode(&proof).unwrap(),
                };
                (agent, call)
            })
            .collect()
    }

    /// The node's stats, read as its operator.
    fn stats(&self) -> Vec<Stage> {
        let node = client::node_id(&self.target).unwrap();
        let operator = Operator::signing(&self.target, SigningKey::from_bytes(&OPERATOR), node);
        match operator.stats().unwrap() {
            Response::Stats(stats) => stats.stages,
            other => panic!("not stats: {other:?}"),
        }
    }
}

/// A run's sends: the latency of each from when it was due, the seconds
/// from the first due to the last answered, and the calls in flight, on
/// average (the time spent sending over the run's) and at most.
struct Driven {
    latencies: Vec<Duration>,
    elapsed: f64,
    in_flight: f64,
    most: usize,
}

/// Each of `count` sends at `rate` a second, open loop, by `SENDERS`
/// threads. `send` makes the `i`th.
fn drive(count: usize, rate: f64, send: impl Fn(usize, usize) -> bool + Sync) -> Driven {
    let next = AtomicUsize::new(0);
    let (flying, most, sending) = (AtomicUsize::new(0), AtomicUsize::new(0), AtomicU64::new(0));
    let start = Instant::now() + Duration::from_millis(100);
    let latencies = std::sync::Mutex::new(Vec::with_capacity(count));
    std::thread::scope(|scope| {
        for sender in 0..SENDERS {
            let (next, latencies, send) = (&next, &latencies, &send);
            let (flying, most, sending) = (&flying, &most, &sending);
            scope.spawn(move || {
                loop {
                    let index = next.fetch_add(1, Ordering::SeqCst);
                    if index >= count {
                        return;
                    }
                    let due = start + Duration::from_secs_f64(index as f64 / rate);
                    if let Some(wait) = due.checked_duration_since(Instant::now()) {
                        std::thread::sleep(wait);
                    }
                    most.fetch_max(flying.fetch_add(1, Ordering::SeqCst) + 1, Ordering::SeqCst);
                    let sent = Instant::now();
                    assert!(send(sender, index), "call {index} did not run");
                    sending.fetch_add(sent.elapsed().as_nanos() as u64, Ordering::Relaxed);
                    flying.fetch_sub(1, Ordering::SeqCst);
                    latencies.lock().unwrap().push(due.elapsed());
                }
            });
        }
    });
    let elapsed = start.elapsed().as_secs_f64();
    let mut latencies = latencies.into_inner().unwrap();
    latencies.sort();
    Driven {
        latencies,
        elapsed,
        in_flight: sending.into_inner() as f64 / 1e9 / elapsed,
        most: most.into_inner(),
    }
}

fn percentile(sorted: &[Duration], at: usize) -> f64 {
    sorted[(sorted.len() * at / 100).min(sorted.len() - 1)].as_secs_f64() * 1e3
}

/// A stage's count and mean in ms between two reads of the stats.
fn between(before: &[Stage], after: &[Stage], name: &str) -> (u64, f64) {
    let read = |stages: &[Stage]| {
        stages
            .iter()
            .find(|stage| stage.name == name)
            .map_or((0, 0), |stage| {
                (stage.counts.iter().sum::<u64>(), stage.total)
            })
    };
    let ((count, total), (count_before, total_before)) = (read(after), read(before));
    let count = count - count_before;
    (
        count,
        (total - total_before) as f64 / count.max(1) as f64 / 1e3,
    )
}

/// One run at `k`: the proofs made, the credentialed calls and then the
/// signed increments sent, and the line that reports them.
fn run(reached: &Reached, client_target: &Target, executors: usize, seconds: f64) {
    let rate = 100.0 * executors as f64;
    let started = Instant::now();
    let calls = Arc::new(reached.calls(rate, seconds));
    let count = calls.len();
    let proving = started.elapsed();
    let before = reached.stats();
    let credentialed = drive(count, rate, |_, index| {
        let (agent, call) = &calls[index];
        client::credentialed(client_target, *agent, call).is_ok_and(|answer| ran(&answer))
    });
    let after = reached.stats();
    drop(calls);
    let increment: MethodId = method(&actor("counter"), "increment");
    let clients: Vec<std::sync::Mutex<Client>> = (0..SENDERS)
        .map(|sender| {
            let mut seed = [9u8; 32];
            seed[..8].copy_from_slice(&(sender as u64).to_le_bytes());
            std::sync::Mutex::new(Client::new(client_target, SigningKey::from_bytes(&seed)))
        })
        .collect();
    let agents = reached.agents.clone();
    let signed = drive(count, rate, |sender, index| {
        let agent = agents[index % agents.len()];
        clients[sender]
            .lock()
            .unwrap()
            .call(agent, COUNTER, increment, &1u64.encode())
            .is_ok_and(|answer| ran(&answer))
    });
    let achieved = count as f64 / credentialed.elapsed;
    let (c99, s99) = (
        percentile(&credentialed.latencies, 99),
        percentile(&signed.latencies, 99),
    );
    let pass = achieved >= rate * 0.99 && c99 - s99 <= 50.0;
    println!(
        "k = {executors}: {count} proofs made in {:.1} s, sent over {:.1} s; {achieved:.0} a \
         second of {rate:.0} asked; credentialed p50 {:.1} p99 {c99:.1}; signed p50 {:.1} p99 \
         {s99:.1}; {}",
        proving.as_secs_f64(),
        credentialed.elapsed,
        percentile(&credentialed.latencies, 50),
        percentile(&signed.latencies, 50),
        if pass { "within the bound" } else { "MISSED" }
    );
    let (verified, verify) = between(&before, &after, "credential");
    let (_, queue) = between(&before, &after, "credential_queue");
    println!(
        "    {verified} verifications, mean {verify:.2} ms each after {queue:.2} ms waiting for an \
         executor; credentialed calls in flight {:.1} on average, {} at most, of {SENDERS} \
         senders",
        credentialed.in_flight, credentialed.most
    );
}

/// The value after `flag` among `arguments`, taken out of them.
fn take(arguments: &mut Vec<String>, flag: &str) -> Option<String> {
    let at = arguments.iter().position(|argument| argument == flag)?;
    assert!(at + 1 < arguments.len(), "{flag} takes a value");
    let value = arguments.remove(at + 1);
    arguments.remove(at);
    Some(value)
}

fn counts(arguments: &[String]) -> Vec<usize> {
    arguments
        .iter()
        .filter_map(|argument| argument.parse().ok())
        .collect()
}

fn main() {
    // `cargo bench` adds its own flag.
    let mut arguments: Vec<String> = std::env::args()
        .skip(1)
        .filter(|argument| argument != "--bench")
        .collect();
    let host = std::thread::available_parallelism().map_or(1, |cores| cores.get());
    let seconds = take(&mut arguments, "--seconds").map_or(SECONDS, |seconds| {
        seconds.parse().expect("--seconds takes a number")
    });
    assert!(
        seconds * 1e3 + 10_000.0 < LIFE_MS as f64,
        "a run of {seconds} s outlives its proofs"
    );
    match arguments.first().map(String::as_str) {
        Some("serve") => serve(&mut arguments, host),
        Some("drive") => {
            let node = take(&mut arguments, "--node").expect("--node quic://HOST:PORT");
            let key = take(&mut arguments, "--key").expect("--key HEX");
            let space = take(&mut arguments, "--space").expect("--space HEX");
            let agents = take(&mut arguments, "--agents").expect("--agents A,B,…");
            let hex32 = |text: &str| -> [u8; 32] {
                hex::decode(text)
                    .ok()
                    .and_then(|bytes| bytes.try_into().ok())
                    .expect("32 bytes of hex")
            };
            let target = Target::quic(&node, hex32(&key), DRIVER).unwrap();
            let reached = Reached {
                target: target.clone(),
                space: SpaceId(hex32(&space)),
                agents: agents
                    .split(',')
                    .map(|agent| AgentId(agent.parse().expect("an agent's number")))
                    .collect(),
            };
            let [executors] = counts(&arguments)[..] else {
                panic!("drive takes the node's k");
            };
            println!(
                "generator N = {host}; the node at {node}, k = {executors}; {seconds} s; \
                 {SENDERS} senders; latency from when each was due, ms"
            );
            run(&reached, &target, executors, seconds);
        }
        _ => {
            let mut counts = counts(&arguments);
            if counts.is_empty() {
                counts = std::iter::successors(Some(1), |k| Some(k * 2))
                    .take_while(|k| *k < host)
                    .chain([host])
                    .collect();
            }
            println!(
                "host N = {host}; the node and the generator in one process; {AGENTS} agents, \
                 {seconds} s a run, {SENDERS} senders; latency from when each was due, ms"
            );
            for executors in counts {
                let served = start(executors);
                let reached = Reached {
                    target: served.socket.clone(),
                    space: served.space,
                    agents: served.agents.clone(),
                };
                run(&reached, &served.socket, executors, seconds);
                served.node.shutdown();
            }
        }
    }
}

/// The node alone, over QUIC, until its input ends.
fn serve(arguments: &mut Vec<String>, host: usize) {
    let listen = take(arguments, "--listen").expect("--listen ADDRESS");
    let executors = take(arguments, "--executors")
        .map_or(host, |executors| executors.parse().expect("a count"));
    let served = start(executors);
    let driver = SigningKey::from_bytes(&DRIVER).verifying_key().to_bytes();
    let address = served
        .node
        .serve_quic(listen.parse().expect("an address"), vec![driver])
        .unwrap();
    let agents: Vec<String> = served
        .agents
        .iter()
        .map(|agent| agent.0.to_string())
        .collect();
    println!(
        "node: {host} cores it may run on, k = {executors}; drive it with (the host's address \
         for an unspecified one)\n  drive --node \
         quic://{address} --key {} --space {} --agents {} {executors}",
        hex::encode(served.node.id().0),
        hex::encode(served.space.0),
        agents.join(","),
    );
    for _ in std::io::stdin().lock().lines() {}
    served.node.shutdown();
}
