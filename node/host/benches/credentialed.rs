//! The executors' bound (slice 7's 7.11 gate, S44): a node of `k` executor
//! threads, its verification budget their default `2k`, takes at least
//! `100·k` credentialed calls a second, each an owner proof's transfer
//! verified at its ingress, and their 99th percentile latency is within
//! 50 ms of signed calls' at the same rate. No absolute rate is claimed.
//!
//! For each `k` on the command line (1, 2, 4 … up to the host's `N`, and
//! `N`, if none), one node of a founded space of one runs `AGENTS` agents
//! of the purses' ledger and the counter; the proofs are made first, on
//! every core, then sent open loop at `100·k` a second over the node API's
//! socket for `SECONDS`, the latency of each from the time it was due;
//! then signed increments at the same rate, the same way.
//!
//! `cargo bench -p vos-node --bench credentialed -- 1 2 4` (after `just
//! build-agent build-test-actors`).

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use rayon::prelude::*;
use vos_checker::calls::installed;
use vos_checker::programs::{Programs, actor, method, package};
use vos_node::client::{self, Client, Target};
use vos_node::{Config, Node};
use vos_pvm_final_verifier::credential as verifier;
use vos_pvm_recair::credential::{OwnerPublic, Statement, prove};
use vos_pvm_recair::masked::MaskRng;
use vos_wire::credentials::{self as tree, Bound, Tag, Words};
use vos_wire::ids::{AgentId, InstanceId, Principal};
use vos_wire::ingress::{CredentialPublic, Credentialed, Response};
use vos_wire::result::Outcome;
use vos_wire::{Encode, SpaceId, WindowClock};

const PURSES: InstanceId = InstanceId(2);
const COUNTER: InstanceId = InstanceId(1);
const AGENTS: usize = 4;
const SECONDS: u64 = 5;
/// Calls in flight at once, at most: the senders.
const SENDERS: usize = 96;
const OPERATOR: [u8; 32] = [21; 32];

/// One node of a founded space, its agents ready: each with a row
/// `payer`, owned by the secret's owner digest and full, and `payee`.
struct Bench {
    node: Node,
    target: Target,
    space: SpaceId,
    agents: Vec<AgentId>,
    secret: Words,
    _dir: tempfile::TempDir,
}

fn start(executors: usize) -> Bench {
    let programs = Programs::load();
    let dir = tempfile::tempdir_in(std::env::temp_dir()).unwrap();
    let ingress = format!("http://127.0.0.1:{}", vos_checker::spaces::free_tcp_port());
    let space = vos_checker::spaces::space(&programs.agent, &[dir.path()], |_| ingress.clone());
    let genesis = space
        .found(WindowClock::DEFAULT, vos_node::wall_clock(), [3; 16])
        .unwrap();
    let space = space.with_genesis(genesis).unwrap();
    let id = space.id();
    let node = vos_checker::spaces::open_node(1, dir.path(), || {
        let mut config = Config::new(programs.agent.clone());
        config.executors = executors;
        config.space = Some(space.clone());
        config
    });
    let socket = dir.path().join("api.sock");
    node.serve_socket(&socket, 0o600).unwrap();
    let target = Target::socket(socket);
    let secret: Words = core::array::from_fn(|i| 77 + i as u32);
    let owner = tree::digest(&tree::compress(&Tag::Owner.block(), &secret));
    let key = SigningKey::from_bytes(&OPERATOR);
    let operator = Principal::Client(key.verifying_key().to_bytes());
    let mut client = Client::new(&target, key);
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
                assert!(
                    matches!(
                        answer,
                        Response::Ran {
                            outcome: Outcome::Done(_),
                            ..
                        }
                    ),
                    "{method_name}: {answer:?}"
                );
            }
        }
        agents.push(agent);
    }
    Bench {
        node,
        target,
        space: id,
        agents,
        secret,
        _dir: dir,
    }
}

impl Bench {
    /// `count` transfers, each proved by the payer's owner, round the
    /// agents, good until 50 s past when making them all is expected
    /// to end: the time a first round on every core takes, scaled.
    fn calls(&self, count: usize) -> Vec<(AgentId, Credentialed)> {
        let cores = rayon::current_num_threads();
        let started = Instant::now();
        let now = client::time(&self.target).unwrap();
        self.made(cores, now + 115_000);
        let round = started.elapsed().as_millis() as u64;
        let expected = round * (count as u64).div_ceil(cores as u64) * 11 / 10;
        let calls = self.made(count, now + round + expected + 50_000);
        let expires_ms = calls[0].1.expires_ms;
        let now = client::time(&self.target).unwrap();
        assert!(
            (now..now + 120_000).contains(&expires_ms),
            "the proofs took longer than expected to make"
        );
        calls
    }

    fn made(&self, count: usize, expires_ms: u64) -> Vec<(AgentId, Credentialed)> {
        let transfer = method(&actor("purses"), "transfer");
        let arguments = (b"payer".to_vec(), b"payee".to_vec(), 1u64).encode();
        let owner = tree::compress(&Tag::Owner.block(), &self.secret);
        (0..count)
            .into_par_iter()
            .map(|index| {
                let agent = self.agents[index % self.agents.len()];
                let mut nonce = [0u8; 16];
                nonce[..8].copy_from_slice(&(index as u64).to_le_bytes());
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
                    self.secret,
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
}

/// Each of `count` sends at `rate` a second, open loop, by `SENDERS`
/// threads: the latency of each from when it was due, and the seconds from
/// the first due to the last answered. `send` makes the `i`th.
fn drive(
    count: usize,
    rate: f64,
    send: impl Fn(usize, usize) -> bool + Sync,
) -> (Vec<Duration>, f64) {
    let next = AtomicUsize::new(0);
    let start = Instant::now() + Duration::from_millis(100);
    let latencies = std::sync::Mutex::new(Vec::with_capacity(count));
    std::thread::scope(|scope| {
        for sender in 0..SENDERS {
            let (next, latencies, send) = (&next, &latencies, &send);
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
                    assert!(send(sender, index), "call {index} did not run");
                    latencies.lock().unwrap().push(due.elapsed());
                }
            });
        }
    });
    let elapsed = start.elapsed().as_secs_f64();
    (latencies.into_inner().unwrap(), elapsed)
}

fn percentile(sorted: &[Duration], at: usize) -> f64 {
    sorted[(sorted.len() * at / 100).min(sorted.len() - 1)].as_secs_f64() * 1e3
}

fn main() {
    let host = std::thread::available_parallelism().map_or(1, |cores| cores.get());
    let mut counts: Vec<usize> = std::env::args()
        .skip(1)
        .filter_map(|argument| argument.parse().ok())
        .collect();
    if counts.is_empty() {
        counts = std::iter::successors(Some(1), |k| Some(k * 2))
            .take_while(|k| *k < host)
            .chain([host])
            .collect();
    }
    println!(
        "host N = {host}; {AGENTS} agents, {SECONDS} s a run, {SENDERS} senders; latency from \
         when each was due, ms"
    );
    for executors in counts {
        let bench = start(executors);
        let rate = 100.0 * executors as f64;
        let count = (rate as usize) * SECONDS as usize;
        let started = Instant::now();
        let calls = Arc::new(bench.calls(count));
        let proving = started.elapsed();
        let target = bench.target.clone();
        let (mut credentialed, elapsed) = drive(count, rate, |_, index| {
            let (agent, call) = &calls[index];
            matches!(
                client::credentialed(&target, *agent, call),
                Ok(Response::Ran {
                    outcome: Outcome::Done(_),
                    ..
                })
            )
        });
        credentialed.sort();
        let increment = method(&actor("counter"), "increment");
        let clients: Vec<std::sync::Mutex<Client>> = (0..SENDERS)
            .map(|sender| {
                let mut seed = [9u8; 32];
                seed[..8].copy_from_slice(&(sender as u64).to_le_bytes());
                std::sync::Mutex::new(Client::new(&bench.target, SigningKey::from_bytes(&seed)))
            })
            .collect();
        let agents = bench.agents.clone();
        let (mut signed, _) = drive(count, rate, |sender, index| {
            let agent = agents[index % agents.len()];
            matches!(
                clients[sender]
                    .lock()
                    .unwrap()
                    .call(agent, COUNTER, increment, &1u64.encode()),
                Ok(Response::Ran {
                    outcome: Outcome::Done(_),
                    ..
                })
            )
        });
        signed.sort();
        let achieved = count as f64 / elapsed;
        let (c99, s99) = (percentile(&credentialed, 99), percentile(&signed, 99));
        let pass = achieved >= rate * 0.99 && c99 - s99 <= 50.0;
        println!(
            "k = {executors}: {count} proofs made in {:.1} s; {achieved:.0} a second of {rate:.0} \
             asked; credentialed p50 {:.1} p99 {c99:.1}; signed p50 {:.1} p99 {s99:.1}; {}",
            proving.as_secs_f64(),
            percentile(&credentialed, 50),
            percentile(&signed, 50),
            if pass { "within the bound" } else { "MISSED" }
        );
        let stats = bench.node.stats();
        if let Some(stage) = stats.stages.iter().find(|stage| stage.name == "credential") {
            let calls: u64 = stage.counts.iter().sum();
            println!(
                "    {calls} verifications, mean {:.2} ms each",
                stage.total as f64 / calls.max(1) as f64 / 1e3
            );
        }
        bench.node.shutdown();
    }
}
