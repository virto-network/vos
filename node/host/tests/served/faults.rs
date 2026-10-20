//! The failures an exactly-once run goes through, one at a time: nodes
//! stopped and restarted, a leader stopped between its apply and its
//! answer or mid-tour, a node cut off, a lossy network, clocks jumping,
//! and every session expired and collected.

use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use vos_checker::rounds::ROUNDS;
use vos_checker::{ANSWERED, ATTEMPT, Client, PAUSING, Random, Touring, wait_until};
use vos_node::Node;
use vos_wire::ids::{AgentId, Session, SessionId, WorkflowId};
use vos_wire::keys::Due;
use vos_wire::peer::NodeNumber;
use vos_wire::records::{Workflow, WorkflowState, unstored};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, defaults, keys};

use crate::exactly_once::tallied;
use crate::harness::{Cluster, NODES, query};

/// How far one node's clock jumps, either way.
const NODE_JUMP: i64 = 15_000;
/// How far every clock jumps ahead, once a run: past the skew and both
/// ways of a node's jump, with 30 s to spare.
const CLUSTER_JUMP: i64 = 120_000;
const _: () = assert!(CLUSTER_JUMP >= defaults::SESSION_SKEW_MS as i64 + 2 * NODE_JUMP + 30_000);
/// Failures a run goes through; clients send until they are over.
const FAULTS: usize = 16;

/// A follower of `agent` stays down until its leader has compacted the log
/// past the follower's last entry, so it comes back by a snapshot however
/// slowly the clients go (within three minutes: a loaded host's clients
/// take more than one to fill a compaction's entries). A skip, or the
/// minutes run out, is logged as such: a later missing snapshot can be
/// traced to it.
fn follower_down_past_compaction(cluster: &Cluster, agent: AgentId) {
    let follower = || {
        let leader = cluster.leader(agent)?;
        (1..=NODES)
            .filter(|number| *number != leader)
            .find_map(|number| Some((number, cluster.node(number)?.replica(agent)?.last_index)))
    };
    let until = Instant::now() + Duration::from_secs(10);
    let (number, last) = loop {
        if let Some(found) = follower() {
            break found;
        }
        if Instant::now() >= until {
            cluster.saw("fault: a follower down past compaction, skipped: no leader and follower");
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    cluster.saw("fault: a follower down past compaction");
    cluster.stop(number);
    let until = Instant::now() + Duration::from_secs(180);
    loop {
        let compacted = cluster
            .leader(agent)
            .and_then(|leader| cluster.node(leader)?.replica(agent))
            .is_some_and(|status| status.log_start > last);
        if compacted {
            break;
        }
        if Instant::now() >= until {
            cluster.saw("fault: a follower down past compaction, the minutes run out");
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    cluster.start(number);
}

/// Workflow `workflow`'s state in `node`'s applied state at `agent`.
fn tour_state(node: &Node, agent: AgentId, workflow: WorkflowId) -> Option<WorkflowState> {
    let bytes = node
        .store()
        .snapshot()
        .get(agent, &keys::workflow(workflow))
        .ok()??;
    Some(Workflow::decode(unstored(&bytes)?).ok()?.0.state)
}

/// Whether a tour in `state` is where a stop aims: preempted between two
/// awaits (`computing`), or else awaiting the next agent's answer.
fn aimed(state: &WorkflowState, computing: bool) -> bool {
    match state {
        WorkflowState::Preempted(_) => computing,
        WorkflowState::Awaiting { .. } => !computing,
        _ => false,
    }
}

/// A leader stopped while a tour of its agent stands where the stop aims,
/// and started again: another leader resumes the tour from that snapshot.
///
/// So that the tour's next step cannot commit before the stop, the
/// leader's refines are held, and the tour must still stand there once
/// everything it proposed before has committed and applied; then it is
/// cut off, so nothing it proposes once let go commits, and stopped.
fn stop_mid_tour(cluster: &Cluster, clients: &[Client], computing: bool, random: &mut Random) {
    let until = Instant::now() + Duration::from_secs(10);
    while Instant::now() < until {
        for client in clients {
            let Some(workflow) = client.tours().and_then(Touring::current) else {
                continue;
            };
            let Some(leader) = cluster.leader(client.agent) else {
                continue;
            };
            let Some(node) = cluster.node(leader) else {
                continue;
            };
            let standing = || {
                tour_state(&node, client.agent, workflow)
                    .is_some_and(|state| aimed(&state, computing))
            };
            if !standing() {
                continue;
            }
            let held = cluster.slot(leader).trip.refines.close();
            // A batch past the gate is proposed, committed and applied.
            std::thread::sleep(Duration::from_millis(50));
            let settled = node.replica(client.agent).is_some_and(|status| {
                status.leads
                    && status.applied == status.commit
                    && status.commit == status.last_index
            });
            if settled && standing() {
                cluster.saw(if computing {
                    "fault: a leader stops mid-computation"
                } else {
                    "fault: a leader stops mid-await"
                });
                cluster.hub.isolate(leader);
                drop(held);
                drop(node);
                cluster.stop(leader);
                cluster.hub.heal();
                std::thread::sleep(Duration::from_millis(100 + random.below(400)));
                cluster.start(leader);
                return;
            }
            drop(held);
        }
        std::thread::sleep(Duration::from_millis(1));
    }
    cluster.saw("fault: a leader stops mid-tour, skipped: none found");
}

/// [`FAULTS`] failures, one at a time: among them every clock jumping
/// past the skew under load, every session expiring, a follower kept
/// down until the log compacts past it, and, with tours, leaders stopped
/// mid-await and mid-computation.
pub(crate) fn faults(cluster: &Cluster, clients: &[Client], random: &mut Random) {
    let touring = clients.iter().any(|client| client.tours().is_some());
    let pause = |random: &mut Random| {
        std::thread::sleep(Duration::from_millis(100 + random.below(400)));
    };
    let agents: Vec<AgentId> = clients
        .iter()
        .map(|client| client.agent)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    for fault in 0..FAULTS {
        pause(random);
        if fault == FAULTS / 4 {
            // Batches timed before the jump refine after it, while their
            // callers, unanswered, send them again.
            cluster.saw("fault: every clock jumps past the skew");
            let held: Vec<_> = (1..=NODES)
                .map(|number| cluster.slot(number).trip.refines.close())
                .collect();
            cluster.offset.fetch_add(CLUSTER_JUMP, Ordering::SeqCst);
            std::thread::sleep(ATTEMPT + Duration::from_millis(500));
            drop(held);
            // A loaded host may take long to reach a session timed before
            // the jump, which the run checks one met: the next faults
            // wait for it.
            vos_checker::poll(PAUSING, || {
                cluster.log.seen().contains_key("session timed again")
            });
            continue;
        }
        if fault == FAULTS / 2 {
            expire_every_session(cluster, clients, random);
            continue;
        }
        if fault == 3 * FAULTS / 4 {
            follower_down_past_compaction(
                cluster,
                agents[random.below(agents.len() as u64) as usize],
            );
            continue;
        }
        if touring && fault % 4 == 2 {
            stop_mid_tour(cluster, clients, fault % 8 == 6, random);
            continue;
        }
        let agent = agents[random.below(agents.len() as u64) as usize];
        let any = 1 + random.below(u64::from(NODES)) as NodeNumber;
        match random.below(6) {
            0 => {
                cluster.saw("fault: stop");
                let number = cluster.leader(agent).unwrap_or(any);
                cluster.stop(number);
                pause(random);
                cluster.start(number);
            }
            1 => {
                // The window path: the leader applies, stops before it
                // answers, and its callers go to the next leader.
                let Some(number) = cluster.leader(agent) else {
                    continue;
                };
                let trip = &cluster.slot(number).trip;
                trip.tripped.store(false, Ordering::SeqCst);
                trip.armed.store(true, Ordering::SeqCst);
                let until = Instant::now() + Duration::from_secs(2);
                while !trip.tripped.load(Ordering::SeqCst) && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(1));
                }
                trip.armed.store(false, Ordering::SeqCst);
                cluster.saw(if trip.tripped.load(Ordering::SeqCst) {
                    "fault: stop between apply and answer"
                } else {
                    "fault: stop, nothing applied"
                });
                cluster.stop(number);
                pause(random);
                cluster.start(number);
            }
            5 => {
                // Clients calling the followers re-forward to the leader
                // they elect.
                cluster.saw("fault: the leader cut off");
                cluster.hub.isolate(cluster.leader(agent).unwrap_or(any));
                pause(random);
                pause(random);
                cluster.hub.heal();
            }
            2 => {
                cluster.saw("fault: isolate");
                cluster.hub.isolate(any);
                pause(random);
                cluster.hub.heal();
            }
            3 => {
                cluster.saw("fault: loss and delay");
                cluster.hub.set_loss(20_000);
                cluster
                    .hub
                    .set_delay(Duration::from_millis(1 + random.below(3)));
                pause(random);
                pause(random);
                cluster.hub.set_loss(0);
                cluster.hub.set_delay(Duration::ZERO);
            }
            _ => {
                // Ahead, then back: a leader that ran ahead leaves the
                // others trailing its time.
                cluster.saw("fault: clock jump");
                let jump = if random.below(2) == 0 {
                    NODE_JUMP
                } else {
                    -NODE_JUMP
                };
                let offset = &cluster.slot(any).offset;
                offset.store(jump, Ordering::SeqCst);
                pause(random);
                pause(random);
                offset.store(0, Ordering::SeqCst);
            }
        }
    }
}

/// Whether `node` holds any of `agent`'s session state: rows of the
/// sessions' kinds, a session's row in the due index, or a count.
fn holds_sessions(node: &Node, agent: AgentId) -> bool {
    let snapshot = node.store().snapshot();
    let any = Session {
        key: [0; 32],
        name: [0; 16],
        t0: 0,
    };
    let live = snapshot
        .get(agent, &keys::live_sessions())
        .unwrap()
        .map(|bytes| u64::decode(unstored(&bytes).unwrap()).unwrap().0);
    // A key of each session kind, for its first two bytes: the prefix every
    // row of that kind shares.
    let rows = [
        keys::session_index(&any),
        keys::session_of(SessionId(0)),
        keys::session(SessionId(0)),
        keys::reply(SessionId(0), 0),
        keys::key_sessions(&[0; 32]),
    ]
    .iter()
    .any(|key| snapshot.scan(agent, &key[..2], None).next().is_some());
    // Workflows share the due index.
    let due = snapshot.scan(agent, &keys::due_prefix(), None).any(|row| {
        let (key, _) = row.unwrap();
        matches!(keys::due_entry(&key), Some((_, Due::Session(_))))
    });
    rows || due || live.is_some_and(|live| live > 0)
}

/// Clients pause with every request answered, each keeping one it ran and
/// one signed but never sent; every clock moves past the expiry, and every
/// replica collects every session while a leader stops. Sent again to
/// every node, neither captured request runs, and every counter stays.
fn expire_every_session(cluster: &Cluster, clients: &[Client], random: &mut Random) {
    cluster.saw("fault: every session expires");
    cluster.paused.store(true, Ordering::SeqCst);
    wait_until("the clients pause", PAUSING, || {
        clients.iter().all(Client::idle)
    });
    let captured: Vec<Vec<Vec<u8>>> = clients
        .iter()
        .map(|client| client.capture(cluster))
        .collect();
    cluster.offset.fetch_add(
        (defaults::SESSION_EXPIRY_MS + defaults::SESSION_BUCKET_MS + 60_000) as i64,
        Ordering::SeqCst,
    );
    let agent = clients[random.below(clients.len() as u64) as usize].agent;
    if let Some(leader) = cluster.leader(agent) {
        cluster.stop(leader);
        std::thread::sleep(Duration::from_millis(100 + random.below(400)));
        cluster.start(leader);
    }
    wait_until("every replica collects every session", ANSWERED, || {
        (1..=NODES).all(|number| {
            cluster.node(number).is_some_and(|node| {
                clients
                    .iter()
                    .all(|client| !holds_sessions(&node, client.agent))
            })
        })
    });
    for (client, captured) in clients.iter().zip(&captured) {
        client.replay(cluster, captured);
    }
    cluster.saw("captured requests refused");
    for client in clients {
        // Every tour ended: its own tallies are as they stay.
        if let Some(touring) = client.tours() {
            for number in 1..=NODES {
                let node = cluster.node(number).unwrap();
                let checked = tallied(&node, client.agent, ROUNDS, touring);
                assert!(checked.is_ok(), "client {}: {checked:?}", client.number);
            }
            continue;
        }
        let (instance, method, total) = (
            client.instance,
            client.methods.value,
            client.total(client.sent()),
        );
        for number in 1..=NODES {
            let node = cluster.node(number).unwrap();
            wait_until("every counter as it was", ANSWERED, || {
                query(&node, client.agent, instance, method) == Ok(Outcome::Done(total.encode()))
            });
        }
    }
    cluster.paused.store(false, Ordering::SeqCst);
}
