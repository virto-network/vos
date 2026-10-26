//! Exactly once across processes, through faults: five `vos node run`
//! processes, six agents each on three of them and a few hundred idle
//! ones, and two clients at each agent on the checker's model
//! (`vos-checker`), while a seed picks the faults:
//! - a node killed, often a leader, and restarted; a node paused;
//! - a connection cut, a link cut, a node cut off, a link losing or
//!   delaying datagrams;
//! - a gray failure, a node's Raft frames lost while its pair heartbeat
//!   flows, and the reverse;
//! - a slow disk, a stalled one, and a failing one, whose node halts and
//!   is restarted;
//! - a node's clock jumping either way, and once every node's past the
//!   session skew;
//! - replicas replaced, among them the current leader, and once in the
//!   shape that leaves a retired replica's vote floor the only guard;
//! - once, every session expiring and collected, and requests captured
//!   before sent again; and once, a group without a quorum for a while.
//!
//! Every answer must be its client's running total, every read must agree
//! with what was answered, and no captured request may run. At the end
//! every replica applies through its leader's commit and holds the same
//! entries and rows, and no node panicked or halted but those whose disk
//! failed.
//!
//! In the clear or over TLS by the seed's parity, its clients one request
//! at a time or pipelined by the next bit. The seed is printed;
//! `FAULTS_SEED` runs one again.

#![cfg(feature = "faults")]

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use vos_checker::processes::relay::Link;
use vos_checker::processes::{Options, PROCESS_WAIT, Processes};
use vos_checker::programs::package;
use vos_checker::{
    ANSWERED, COUNTER, Client, INBOX, Mode, Nodes, PAUSING, Random, SECOND, mark, wait_until,
};
use vos_node::store::Fjall;
use vos_wire::ids::AgentId;
use vos_wire::ingress::{Consistency, Response, Unplaced};
use vos_wire::peer::NodeNumber;
use vos_wire::{defaults, keys};

const NODES: usize = 5;
/// Agents the clients call, each on three nodes.
const AGENTS: usize = 6;
/// Agents nobody calls, besides: their placements and groups come with
/// every restart and election.
const IDLE: usize = 200;
/// Faults a run goes through, one at a time but for a window without a
/// quorum.
const FAULTS: usize = 24;
/// How far one node's clock jumps, either way.
const NODE_JUMP: i64 = 15_000;
/// How far every clock jumps ahead, once a run: past the skew and both
/// ways of a node's jump, with 30 s to spare.
const EVERY_JUMP: i64 = 120_000;
const _: () = assert!(EVERY_JUMP >= defaults::SESSION_SKEW_MS as i64 + 2 * NODE_JUMP + 30_000);
/// The nodes' settings: elections of 300–600 ms, so a run sees many;
/// logs compacted every few dozen entries, so a restarted replica catches
/// up by a snapshot; QUIC connections that a cut of a few seconds
/// outlasts.
const SETTINGS: &str = "election_ms 300 600\nheartbeat_ms 100\ncompact 32 8\nquic_idle 5000\n";
/// The longest election timeout `SETTINGS` names.
const ELECTION_HIGH: Duration = Duration::from_millis(600);

/// The run: its nodes, and where each agent the clients call is placed.
struct Run {
    space: Processes,
    random: Mutex<Random>,
    placements: Mutex<BTreeMap<AgentId, Vec<usize>>>,
    /// Each disk made to fail: its node, and where its log stood before
    /// the fault and after its restart. A halt is expected there only.
    failed_disks: Mutex<Vec<(usize, u64, u64)>>,
}

impl Run {
    fn below(&self, bound: u64) -> u64 {
        self.random.lock().unwrap().below(bound)
    }

    /// A pause of `low` to `high` milliseconds.
    fn pause(&self, low: u64, high: u64) {
        std::thread::sleep(Duration::from_millis(low + self.below(high - low + 1)));
    }

    fn any_node(&self) -> usize {
        1 + self.below(NODES as u64) as usize
    }

    fn replicas(&self, agent: AgentId) -> Vec<usize> {
        self.placements.lock().unwrap()[&agent].clone()
    }

    fn agents(&self) -> Vec<AgentId> {
        self.placements.lock().unwrap().keys().copied().collect()
    }

    fn any_agent(&self) -> AgentId {
        let agents = self.agents();
        agents[self.below(agents.len() as u64) as usize]
    }

    /// The node leading `agent`, or one of its replicas if none is known.
    fn leader_of(&self, agent: AgentId) -> usize {
        let replicas = self.replicas(agent);
        self.space
            .leading(agent)
            .filter(|leader| replicas.contains(leader))
            .unwrap_or_else(|| replicas[self.below(replicas.len() as u64) as usize])
    }

    fn saw(&self, what: &'static str) {
        self.space.log().saw(what);
        self.space.log().event(what.to_string());
    }

    /// Replace `agent`'s replica `remove` by `add`, at whichever node
    /// leads it, sending again until it is done.
    fn replace(&self, agent: AgentId, remove: usize, add: usize) {
        self.space
            .log()
            .event(format!("replace {remove} by {add} at agent {}", agent.0));
        self.space.operate(
            |operator| {
                operator
                    .replace(agent, remove as NodeNumber, add as NodeNumber)
                    .unwrap_or(Response::Unavailable)
            },
            // Sent again after it was made: done already.
            |answer| {
                matches!(
                    answer,
                    Response::Placed(_)
                        | Response::Unplaced(Unplaced::NotAReplica | Unplaced::AlreadyAReplica)
                )
            },
        );
        let mut placements = self.placements.lock().unwrap();
        let replicas = placements.get_mut(&agent).unwrap();
        replicas.retain(|replica| *replica != remove);
        replicas.push(add);
    }

    /// A spare for `agent`: a running node that does not replicate it.
    fn spare(&self, agent: AgentId) -> Option<usize> {
        let replicas = self.replicas(agent);
        let spares: Vec<usize> = (1..=NODES)
            .filter(|node| !replicas.contains(node) && self.space.is_running(*node))
            .collect();
        (!spares.is_empty()).then(|| spares[self.below(spares.len() as u64) as usize])
    }
}

/// One fault, healed before it returns.
fn fault(run: &Run) {
    let space = &run.space;
    let agent = run.any_agent();
    let node = run.any_node();
    match run.below(15) {
        0 | 1 => {
            run.saw("fault: a leader killed");
            let leader = run.leader_of(agent);
            space.kill(leader);
            run.pause(300, 2000);
            space.restart(leader);
        }
        2 => {
            run.saw("fault: a node paused");
            space.stop(node);
            run.pause(1000, 5000);
            space.resume(node);
        }
        3 => {
            run.saw("fault: a connection cut");
            let peer = 1 + (node + run.below(NODES as u64 - 1) as usize) % NODES;
            space.relay.cut_connection(node, peer);
            run.pause(2000, 10_000);
            space.relay.heal();
        }
        4 => {
            run.saw("fault: a link cut");
            let to = 1 + (node + run.below(NODES as u64 - 1) as usize) % NODES;
            space.relay.cut_link(node, to);
            run.pause(2000, 10_000);
            space.relay.heal();
        }
        5 => {
            run.saw("fault: a leader cut off");
            space.relay.isolate(run.leader_of(agent));
            run.pause(2000, 10_000);
            space.relay.heal();
        }
        6 => {
            let to = 1 + (node + run.below(NODES as u64 - 1) as usize) % NODES;
            let link = if run.below(2) == 0 {
                run.saw("fault: a lossy link");
                Link {
                    loss: 300_000 + run.below(600_000) as u32,
                    delay: Duration::ZERO,
                }
            } else {
                run.saw("fault: a slow link");
                Link {
                    loss: 0,
                    delay: Duration::from_millis(20 + run.below(180)),
                }
            };
            space.relay.set_link(node, to, link);
            space.relay.set_link(to, node, link);
            run.pause(2000, 5000);
            space.relay.heal();
        }
        7 => {
            // Its leader steps down only after its patience: a few
            // election timeouts.
            run.saw("fault: a gray leader");
            let leader = run.leader_of(agent);
            space.set_faults(leader, "drop consensus 1000000\n");
            run.pause(4000, 8000);
            space.set_faults(leader, "");
        }
        14 => {
            // The reverse: its Raft frames flow, its pair heartbeat does
            // not, and its groups' timers lapse on their own.
            run.saw("fault: a node's pair heartbeat lost");
            space.set_faults(node, "drop liveness 1000000\n");
            run.pause(2000, 5000);
            space.set_faults(node, "");
        }
        8 => {
            run.saw("fault: a slow disk");
            space.set_faults(node, &format!("delay_commits {}\n", 20 + run.below(180)));
            run.pause(2000, 5000);
            space.set_faults(node, "");
        }
        9 => {
            run.saw("fault: a stalled disk");
            space.set_faults(node, "hold_commits\n");
            run.pause(2000, 5000);
            space.set_faults(node, "");
        }
        10 => {
            // A node that flushes: a replica of an agent the clients call.
            run.saw("fault: a failing disk");
            let replicas = run.replicas(agent);
            let failing = replicas[run.below(replicas.len() as u64) as usize];
            let from = space.log_len(failing);
            let how = if run.below(2) == 0 { "before" } else { "after" };
            space.set_faults(failing, &format!("fail_commits {how}\n"));
            wait_until("the failing node halts", PROCESS_WAIT, || {
                space
                    .status(failing, agent)
                    .is_some_and(|status| status.halted)
            });
            space.kill(failing);
            run.pause(100, 1000);
            space.restart(failing);
            let to = space.log_len(failing);
            run.failed_disks.lock().unwrap().push((failing, from, to));
        }
        11 => {
            run.saw("fault: a clock jump");
            let jump = if run.below(2) == 0 {
                NODE_JUMP
            } else {
                -NODE_JUMP
            };
            space.jump_clock(node, jump);
            run.pause(1000, 3000);
            space.jump_clock(node, 0);
        }
        12 => {
            run.saw("fault: a replica replaced");
            let replicas = run.replicas(agent);
            let remove = replicas[run.below(replicas.len() as u64) as usize];
            if let Some(add) = run.spare(agent) {
                run.replace(agent, remove, add);
            }
        }
        _ => {
            run.saw("fault: the leader replaced");
            let leader = run.leader_of(agent);
            if let Some(add) = run.spare(agent) {
                run.replace(agent, leader, add);
            }
        }
    }
}

/// The shape a retired replica's vote floor guards: a stale replica, and
/// an empty one added again that could vote for it.
/// 1. Group {a, b, c}, spares d and e: a is killed.
/// 2. a is replaced by d: a is stale.
/// 3. b is replaced by e: b retires, keeping its floor.
/// 4. With c, d and e sending b no Raft frames, e is replaced by b: b is
///    added again, empty but for its floor, and hears no leader.
/// 5. a restarts, and no other node tells it of the placement that
///    removed it: it campaigns in its old configuration. c refuses it, so
///    only b's floor stands between it and a majority, a and b. It must
///    never lead.
fn floor_aimed(run: &Run) {
    let space = &run.space;
    run.saw("fault: replacements aimed at the vote floor");
    let agent = run.any_agent();
    let replicas = run.replicas(agent);
    let a = replicas[run.below(3) as usize];
    let others: Vec<usize> = replicas.iter().copied().filter(|node| *node != a).collect();
    let (b, c) = (others[0], others[1]);
    space.kill(a);
    let d = run.spare(agent).expect("a spare");
    run.replace(agent, a, d);
    let e = run.spare(agent).expect("a second spare");
    run.replace(agent, b, e);
    // e may lead when b is added again: none of the group's other nodes
    // sends b anything that would fill it, or make it hear a leader.
    let unheard = format!("drop requests 1000000 to {a}\n");
    let cut = format!("{unheard}drop consensus 1000000 to {b}\ndrop bulk 1000000 to {b}\n");
    for node in [c, d, e] {
        space.set_faults(node, &cut);
    }
    space.set_faults(b, &unheard);
    run.replace(agent, e, b);
    wait_until("b runs the group again, empty", PROCESS_WAIT, || {
        space
            .status(b, agent)
            .is_some_and(|status| status.applied == 0 && !status.leads)
    });
    space.restart(a);
    // a never leads: through its first refusals, which may only raise its
    // term to b's, and two of its election timeouts after.
    let started = std::time::Instant::now();
    let mut caught_up: Option<std::time::Instant> = None;
    while caught_up.is_none_or(|at| at.elapsed() < 2 * ELECTION_HIGH)
        && started.elapsed() < Duration::from_secs(10)
    {
        let stale = space.status(a, agent);
        let empty = space.status(b, agent);
        if let Some(stale) = &stale {
            assert!(
                !stale.leads,
                "agent {}: stale node {a} leads at term {}, an empty node {b} voting for it",
                agent.0, stale.term
            );
        }
        if let Some(empty) = &empty {
            assert_eq!(empty.applied, 0, "agent {}: node {b} was filled", agent.0);
        }
        if let (Some(stale), Some(empty), None) = (&stale, &empty, caught_up)
            && stale.term >= empty.term
        {
            caught_up = Some(std::time::Instant::now());
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    if caught_up.is_some() {
        run.saw("a stale replica campaigned, and the floor held");
    }
    for node in [b, c, d, e] {
        space.set_faults(node, "");
    }
}

/// Two of a group's three replicas down together for a while: nothing
/// may be lost, and once they are back the group goes on.
fn quorum_lost(run: &Run) {
    run.saw("fault: a quorum lost");
    let agent = run.any_agent();
    let replicas = run.replicas(agent);
    let down: Vec<usize> = replicas.iter().copied().take(2).collect();
    for node in &down {
        run.space.kill(*node);
    }
    run.pause(3000, 8000);
    for node in &down {
        run.space.restart(*node);
    }
}

/// Clients pause with every request answered, each keeping one it ran and
/// one signed but never sent; every clock moves past the expiry, and every
/// replica collects every session while a leader is killed and restarted.
/// Sent again to every node, neither captured request runs, and every
/// counter stays.
fn expire_every_session(run: &Run, clients: &[Client]) {
    let space = &run.space;
    run.saw("fault: every session expires");
    space.clients_paused.store(true, Ordering::SeqCst);
    // A client finishes the request it is sending first.
    wait_until("the clients pause", PAUSING, || {
        clients.iter().all(Client::idle)
    });
    let captured: Vec<Vec<Vec<u8>>> = clients.iter().map(|client| client.capture(space)).collect();
    space.jump_every_clock(
        (defaults::SESSION_EXPIRY_MS + defaults::SESSION_BUCKET_MS + 60_000) as i64,
    );
    let leader = run.leader_of(run.any_agent());
    space.kill(leader);
    run.pause(100, 500);
    space.restart(leader);
    wait_until("every replica collects every session", ANSWERED, || {
        run.agents().into_iter().all(|agent| {
            run.replicas(agent).into_iter().all(|replica| {
                space
                    .status(replica, agent)
                    .is_some_and(|status| status.sessions == 0)
            })
        })
    });
    for (client, captured) in clients.iter().zip(&captured) {
        client.replay(space, captured);
    }
    run.saw("captured requests refused");
    for client in clients {
        let total = client.total(client.sent());
        for replica in run.replicas(client.agent) {
            wait_until("every counter as it was", PROCESS_WAIT, || {
                client
                    .read_at(
                        space,
                        replica as NodeNumber,
                        client.instance,
                        Consistency::Linearizable,
                    )
                    .is_ok_and(|(value, _)| value == total)
            });
        }
    }
    space.clients_paused.store(false, Ordering::SeqCst);
}

/// Ends the clients and readers when the faults are over, or have failed:
/// they stop pausing, and stop.
struct Ending<'a>(&'a AtomicBool, &'a Processes);

impl Drop for Ending<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
        self.1.clients_paused.store(false, Ordering::SeqCst);
    }
}

/// An agent's applied state: its rows, keys and values.
type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// Every replica of `agent`, settled at `settled`, applied through it and
/// as far as the others, holds the same entries above the highest log
/// start through the lowest commit, and the same rows.
fn stores_agree(stores: &[(usize, &Fjall)], agent: AgentId, settled: u64) {
    let rows: Vec<_> = stores
        .iter()
        .map(|(node, store)| {
            let raft = store.raft(agent).unwrap();
            assert!(
                raft.applied >= settled,
                "agent {}: node {node} applied through {} on disk, settled at {settled}",
                agent.0,
                raft.applied
            );
            (*node, *store, raft)
        })
        .collect();
    assert!(
        rows.windows(2)
            .all(|pair| pair[0].2.applied == pair[1].2.applied),
        "agent {}: the replicas applied through {:?}",
        agent.0,
        rows.iter()
            .map(|(node, _, raft)| (node, raft.applied))
            .collect::<Vec<_>>()
    );
    let from = rows
        .iter()
        .map(|(_, _, raft)| raft.log_start.0)
        .max()
        .unwrap()
        + 1;
    let through = rows
        .iter()
        .map(|(_, _, raft)| raft.hard.commit)
        .min()
        .unwrap();
    for index in from..=through {
        let entries: Vec<_> = rows
            .iter()
            .map(|(node, store, _)| {
                let entry = store.log_entry(agent, index).unwrap();
                assert!(
                    entry.is_some(),
                    "agent {}: node {node} holds no entry {index}",
                    agent.0
                );
                (*node, entry)
            })
            .collect();
        assert!(
            entries.windows(2).all(|pair| pair[0].1 == pair[1].1),
            "agent {}: the replicas' entries at {index} differ: {:?}",
            agent.0,
            entries
                .iter()
                .map(|(node, entry)| (node, entry.as_ref().map(|entry| entry.term)))
                .collect::<Vec<_>>()
        );
    }
    let applied: Vec<(usize, u64, Rows)> = rows
        .iter()
        .map(|(node, store, raft)| {
            let snapshot = store.snapshot();
            (
                *node,
                raft.applied,
                vos_checker::state_rows(&snapshot, agent),
            )
        })
        .collect();
    for (at, (node, index, state)) in applied.iter().enumerate() {
        assert!(
            !state.is_empty(),
            "agent {}: node {node} holds no rows",
            agent.0
        );
        for (other, other_index, other_state) in &applied[at + 1..] {
            if index == other_index {
                assert!(
                    state == other_state,
                    "agent {}: nodes {node} and {other} applied through {index} differ",
                    agent.0
                );
            }
        }
    }
}

#[test]
fn five_processes_apply_once_through_faults() {
    let seed = std::env::var("FAULTS_SEED")
        .ok()
        .and_then(|seed| seed.parse().ok())
        .unwrap_or(0x5eed_0003_u64);
    let (tls, mode, api) = (
        !seed.is_multiple_of(2),
        if (seed >> 1).is_multiple_of(2) {
            Mode::OneAtATime
        } else {
            Mode::Pipelined
        },
        !(seed >> 2).is_multiple_of(2),
    );
    println!("seed {seed}: tls {tls}, {mode:?}, api {api}");
    let space = Processes::start(
        env!("CARGO_BIN_EXE_vos"),
        NODES,
        Options {
            tls,
            api,
            settings: SETTINGS.to_string(),
            ..Options::default()
        },
    );
    let run = Run {
        space,
        // Never zero, as the generator needs, and a different one for
        // each seed.
        random: Mutex::new(Random::new(seed.wrapping_mul(2))),
        placements: Mutex::new(BTreeMap::new()),
        failed_disks: Mutex::new(Vec::new()),
    };
    let space = &run.space;
    let counter = package("counter");
    // Each agent on three nodes in turn, so every node holds some.
    let agents: Vec<AgentId> = (0..AGENTS)
        .map(|at| {
            let replicas: Vec<usize> = (0..3).map(|step| 1 + (at + step) % NODES).collect();
            let agent = space.agent_with(
                replicas.iter().map(|node| *node as NodeNumber).collect(),
                &counter,
                // The inbox first: no message reaches an instance not
                // there yet.
                &[INBOX, COUNTER, SECOND],
            );
            run.placements.lock().unwrap().insert(agent, replicas);
            agent
        })
        .collect();
    std::thread::scope(|scope| {
        for part in 0..4 {
            let run = &run;
            scope.spawn(move || {
                for at in (part..IDLE).step_by(4) {
                    let replicas = (0..3)
                        .map(|step| (1 + (at * 7 + step) % NODES) as NodeNumber)
                        .collect();
                    run.space.agent_with(replicas, &[], &[]);
                }
            });
        }
    });
    let methods = space.methods(agents[0], COUNTER);
    let agents: Vec<(AgentId, [u8; 32])> = agents
        .iter()
        .map(|agent| (*agent, space.identity(*agent)))
        .collect();
    // At each agent, one client forwarding to the next agent's inbox and a
    // second incrementing a counter of its own.
    let clients = vos_checker::clients(&agents, 2 * AGENTS as u8, methods, None, |bound| {
        run.below(bound)
    });
    let forwarding = &clients[..AGENTS];
    let done = AtomicBool::new(false);
    let sent: Vec<u64> = std::thread::scope(|scope| {
        let running: Vec<_> = clients
            .iter()
            .map(|client| scope.spawn(|| client.run(space, mode, &done)))
            .collect();
        for (at, client) in forwarding.iter().enumerate() {
            let previous = &forwarding[(at + AGENTS - 1) % AGENTS];
            let done = &done;
            scope.spawn(move || client.read(space, done, previous));
        }
        let ending = Ending(&done, space);
        for at in 0..FAULTS {
            run.pause(200, 1000);
            match at {
                _ if at == FAULTS / 4 => {
                    run.saw("fault: every clock jumps past the skew");
                    space.jump_every_clock(EVERY_JUMP);
                }
                _ if at == FAULTS / 3 => floor_aimed(&run),
                _ if at == FAULTS / 2 => expire_every_session(&run, &clients),
                _ if at == 3 * FAULTS / 4 => quorum_lost(&run),
                _ => fault(&run),
            }
        }
        drop(ending);
        running
            .into_iter()
            .map(|client| {
                client
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect()
    });
    println!("requests answered: {sent:?}");
    println!("{:?}", space.log().seen());
    // Healed, with every node up, every replica applies through its
    // leader's commit, and holds every request once.
    space.relay.heal();
    for node in 1..=NODES {
        if space.is_running(node) {
            space.set_faults(node, "");
            space.jump_clock(node, 0);
        } else {
            space.restart(node);
        }
    }
    // Settled: every replica applied all its leader holds, and every
    // message was acknowledged.
    // `agent`'s commit if it is settled: its leader's log committed
    // through its end, applied at every replica, every outbox empty.
    let settled = |agent: AgentId| -> Option<u64> {
        let replicas = run.replicas(agent);
        let statuses: Vec<_> = replicas
            .iter()
            .filter_map(|replica| space.status(*replica, agent))
            .collect();
        let leader = statuses
            .iter()
            .filter(|status| status.leads)
            .max_by_key(|status| status.term)?;
        (statuses.len() == replicas.len()
            && leader.last_index == leader.commit
            && statuses
                .iter()
                .all(|status| status.applied == leader.commit && status.outbox == 0))
        .then_some(leader.commit)
    };
    // Every agent settled, read in one pass.
    let settle_all = || -> BTreeMap<AgentId, u64> {
        let mut all = BTreeMap::new();
        wait_until("every agent settles", PROCESS_WAIT, || {
            all = run
                .agents()
                .into_iter()
                .filter_map(|agent| Some((agent, settled(agent)?)))
                .collect();
            all.len() == run.agents().len()
        });
        all
    };
    settle_all();
    for (at, client) in clients.iter().enumerate() {
        let total = client.total(sent[at]);
        for replica in run.replicas(client.agent) {
            wait_until("every counter holds its total", PROCESS_WAIT, || {
                client
                    .read_at(
                        space,
                        replica as NodeNumber,
                        client.instance,
                        Consistency::Linearizable,
                    )
                    .is_ok_and(|(value, _)| value == total)
            });
        }
        if let Some(next) = client.next_agent() {
            let inbox = client.forwarded(sent[at]);
            let reader = &forwarding[(at + 1) % AGENTS];
            for replica in run.replicas(next) {
                wait_until("every inbox holds what was forwarded", PROCESS_WAIT, || {
                    reader
                        .read_at(
                            space,
                            replica as NodeNumber,
                            INBOX,
                            Consistency::Linearizable,
                        )
                        .is_ok_and(|(value, _)| value == inbox)
                });
            }
        }
    }
    println!(
        "the relay lost {} datagrams of itself",
        space.relay.own_drops()
    );
    // Settled again after the reads, every agent in one pass, and stopped
    // at once: an election in between would leave a leader an entry
    // ahead.
    let settled = settle_all();
    let stores = space.stop_all();
    for (agent, settled) in &settled {
        let replicas: Vec<(usize, &Fjall)> = run
            .replicas(*agent)
            .into_iter()
            .map(|replica| (replica, &stores[replica - 1]))
            .collect();
        stores_agree(&replicas, *agent, *settled);
    }
    // Each forward applied once at the receiver, and sent once.
    for (at, client) in forwarding.iter().enumerate() {
        let next = client.next_agent().unwrap();
        let forwards = client.forwards_through(sent[at]);
        for replica in run.replicas(client.agent) {
            let store = &stores[replica - 1];
            assert_eq!(mark(store, client.agent, &keys::pair_out(next)), forwards);
            assert_eq!(mark(store, client.agent, &keys::acked(next)), forwards);
            assert_eq!(
                store
                    .snapshot()
                    .scan(client.agent, &keys::outbox_prefix(), None)
                    .count(),
                0,
                "every message acknowledged"
            );
        }
        for replica in run.replicas(next) {
            assert_eq!(
                mark(&stores[replica - 1], next, &keys::pair_in(client.agent)),
                forwards
            );
        }
    }
    // No panic, no exit the harness did not make, and a halt only while
    // a disk was made to fail.
    assert!(space.exits().is_empty(), "{:?}", space.exits());
    let failed_disks = run.failed_disks.lock().unwrap().clone();
    for node in 1..=NODES {
        for (at, line) in space.trouble_lines(node) {
            assert!(
                !line.contains("panicked")
                    && failed_disks.iter().any(|(failed, from, to)| {
                        *failed == node && (*from..*to).contains(&at)
                    }),
                "node {node}: {line}"
            );
        }
    }
}
