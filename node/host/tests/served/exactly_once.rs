//! Exactly once, over HTTP, through failures: clients increment counters
//! on three nodes, two at each agent, each request resent with its
//! sequence until answered, in sessions they start every few dozen
//! requests, while the nodes stop and start, a leader stops between its
//! apply and its answer, a node is cut off, the network loses and delays
//! frames, a node's clock jumps, and every clock jumps past the skew.
//! Once a run every session expires and is collected while a leader
//! stops, and requests captured before, run or not, are sent again.
//!
//! Every answer must be its client's running total: no request applied
//! twice, none skipped. A node must hold a request applied before it
//! answers it, a captured request never runs, and at the end every
//! replica holds every request once.
//!
//! The seed is printed; `EXACTLY_ONCE_SEED` runs one again.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use vos_checker::programs::{actor, method};
use vos_checker::{
    ANSWERED, ATTEMPT, COUNTER, Client, INBOX, Methods, Mode, Random, SECOND, wait_until,
};
use vos_node::Node;
use vos_wire::ids::{AgentId, InstanceId, Session, SessionId};
use vos_wire::peer::NodeNumber;
use vos_wire::records::unstored;
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, defaults, keys};

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
/// slowly the clients go (within a minute). A skip, or a minute run out, is
/// logged as such: a later missing snapshot can be traced to it.
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
    let until = Instant::now() + Duration::from_secs(60);
    loop {
        let compacted = cluster
            .leader(agent)
            .and_then(|leader| cluster.node(leader)?.replica(agent))
            .is_some_and(|status| status.log_start > last);
        if compacted {
            break;
        }
        if Instant::now() >= until {
            cluster.saw("fault: a follower down past compaction, a minute run out");
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    cluster.start(number);
}

/// [`FAULTS`] failures, one at a time: among them every clock jumping
/// past the skew under load, every session expiring, and a follower kept
/// down until the log compacts past it.
fn faults(cluster: &Cluster, clients: &[Client], random: &mut Random) {
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

/// Whether `node` holds any of `agent`'s session state.
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
    [
        keys::session_index(&any),
        keys::session_of(SessionId(0)),
        keys::session(SessionId(0)),
        keys::reply(SessionId(0), 0),
        keys::due_prefix(),
        keys::key_sessions(&[0; 32]),
    ]
    .iter()
    .any(|key| snapshot.scan(agent, &key[..2], None).next().is_some())
        || live.is_some_and(|live| live > 0)
}

/// Clients pause with every request answered, each keeping one it ran and
/// one signed but never sent; every clock moves past the expiry, and every
/// replica collects every session while a leader stops. Sent again to
/// every node, neither captured request runs, and every counter stays.
fn expire_every_session(cluster: &Cluster, clients: &[Client], random: &mut Random) {
    cluster.saw("fault: every session expires");
    cluster.paused.store(true, Ordering::SeqCst);
    wait_until("the clients pause", ANSWERED, || {
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
        let total = client.total(client.sent());
        for number in 1..=NODES {
            let node = cluster.node(number).unwrap();
            wait_until("every counter as it was", ANSWERED, || {
                query(&node, client.agent, client.instance, client.methods.value)
                    == Ok(Outcome::Done(total.encode()))
            });
        }
    }
    cluster.paused.store(false, Ordering::SeqCst);
}

/// Ends the clients and readers when the faults are over, or have failed:
/// they stop pausing, and stop.
struct Ending<'a>(&'a AtomicBool, &'a Cluster);

impl Drop for Ending<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
        self.1.paused.store(false, Ordering::SeqCst);
    }
}

fn exactly_once(mode: Mode, default_seed: u64) {
    let seed = std::env::var("EXACTLY_ONCE_SEED")
        .ok()
        .and_then(|seed| seed.parse().ok())
        .unwrap_or(default_seed);
    println!("seed {seed}");
    let mut random = Random(seed | 1);
    let cluster = Cluster::new(seed);
    let counter = actor("counter");
    let methods = Methods {
        increment: method(&counter, "increment"),
        value: method(&counter, "value"),
        forward: method(&counter, "forward"),
    };
    let value = methods.value;
    let agents: Vec<(AgentId, [u8; 32])> = (1..=3u8)
        .map(|number| {
            let creator = cluster.node(number).unwrap();
            let agent = creator.create_replicated(vec![1, 2, 3]).unwrap();
            wait_until("a leader", Duration::from_secs(20), || {
                cluster.leader(agent).is_some()
            });
            let leader = cluster.node(cluster.leader(agent).unwrap()).unwrap();
            // The inbox first: no message reaches an instance not there yet.
            for instance in [INBOX, COUNTER, SECOND] {
                let installed =
                    smol::block_on(leader.install(agent, instance, &counter, &[], vec![]));
                assert!(
                    matches!(installed, Ok(vos_node::Reply::Ran(Outcome::Done(_)))),
                    "{installed:?}"
                );
            }
            (agent, cluster.identity(number, agent))
        })
        .collect();
    // At each agent, one client forwarding to the next agent's inbox and a
    // second incrementing a counter of its own: batches mix their
    // sessions, new and held.
    let clients: Vec<Client> = (1..=6u8)
        .map(|number| {
            let (agent, identity) = agents[usize::from(number - 1) % agents.len()];
            let forwarding = number <= 3;
            // The second clients start sessions often: first requests meet
            // every fault.
            let rotate = if forwarding {
                32 + 4 * random.below(8)
            } else {
                4 + 4 * random.below(2)
            };
            Client::new(number, agent, identity, methods, forwarding, rotate)
        })
        .collect();
    let forwarding = &clients[..agents.len()];
    for (at, client) in forwarding.iter().enumerate() {
        let next = &forwarding[(at + 1) % forwarding.len()];
        client.forward_to(next.agent);
    }
    let done = AtomicBool::new(false);
    let sent: Vec<u64> = std::thread::scope(|scope| {
        let running: Vec<_> = clients
            .iter()
            .map(|client| scope.spawn(|| client.run(&cluster, mode, &done)))
            .collect();
        for (at, client) in forwarding.iter().enumerate() {
            let previous = &forwarding[(at + forwarding.len() - 1) % forwarding.len()];
            let (cluster, done) = (&cluster, &done);
            scope.spawn(move || client.read(cluster, done, previous));
        }
        let ending = Ending(&done, &cluster);
        faults(&cluster, &clients, &mut random);
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
    println!("{:?}", cluster.log.seen());
    assert!(
        cluster.log.seen().contains_key("session timed again"),
        "no session met the clocks' jump"
    );
    // Healed, every replica holds every request once.
    cluster.hub.heal();
    for number in 1..=NODES {
        if cluster.node(number).is_none() {
            cluster.start(number);
        }
    }
    let counted =
        |node: &Node, agent: AgentId, instance: InstanceId| query(node, agent, instance, value);
    let mark = |node: &Node, agent: AgentId, key: &[u8]| {
        node.store()
            .snapshot()
            .get(agent, key)
            .unwrap()
            .map(|bytes| u64::decode(unstored(&bytes).unwrap()).unwrap().0)
            .unwrap_or(0)
    };
    for (at, client) in clients.iter().enumerate().skip(forwarding.len()) {
        let total = client.total(sent[at]);
        for number in 1..=NODES {
            let node = cluster.node(number).unwrap();
            wait_until("every replica converges", Duration::from_secs(60), || {
                counted(&node, client.agent, client.instance) == Ok(Outcome::Done(total.encode()))
            });
        }
    }
    for (at, client) in forwarding.iter().enumerate() {
        let sent = sent[at];
        let total = client.total(sent);
        let (next, next_agent) = (
            &forwarding[(at + 1) % forwarding.len()],
            client.next_agent().unwrap(),
        );
        let forwards = sent / 5;
        let inbox = client.forwarded(sent);
        for number in 1..=NODES {
            let node = cluster.node(number).unwrap();
            wait_until("every replica converges", Duration::from_secs(60), || {
                counted(&node, client.agent, COUNTER) == Ok(Outcome::Done(total.encode()))
                    && counted(&node, next_agent, INBOX) == Ok(Outcome::Done(inbox.encode()))
                    && mark(&node, client.agent, &keys::acked(next_agent)) == forwards
                    && node
                        .store()
                        .snapshot()
                        .scan(client.agent, &keys::outbox_prefix(), None)
                        .count()
                        == 0
            });
            // Each forward applied once at the receiver, and was sent once.
            assert_eq!(
                mark(&node, next.agent, &keys::pair_in(client.agent)),
                forwards
            );
            assert_eq!(
                mark(&node, client.agent, &keys::pair_out(next_agent)),
                forwards
            );
        }
    }
    let across: u64 = (1..=NODES)
        .map(|number| {
            cluster.slot(number).sent_across.load(Ordering::SeqCst)
                + cluster.node(number).unwrap().messages_sent_across()
        })
        .sum();
    println!("messages sent across nodes: {across}");
    let installed: u64 = (1..=NODES)
        .map(|number| {
            cluster.slot(number).installed.load(Ordering::SeqCst)
                + cluster.node(number).unwrap().snapshots_installed()
        })
        .sum();
    println!("snapshots installed: {installed}");
    assert!(installed > 0, "no node caught up by a snapshot");
    assert!(across > 0, "no message crossed nodes");
}

#[test]
fn one_request_at_a_time_applies_once_through_failures() {
    exactly_once(Mode::OneAtATime, 0x5eed_0001);
}

#[test]
fn pipelined_requests_apply_once_through_failures() {
    exactly_once(Mode::Pipelined, 0x5eed_0002);
}
