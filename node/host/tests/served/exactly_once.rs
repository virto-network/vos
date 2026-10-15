//! The checker's exactly-once model over HTTP, on three nodes in one
//! process, two clients at each agent, through the failures of
//! [`crate::faults`]. Beside the model's checks, a node must hold a
//! request applied before it answers it.
//!
//! With workflows, a client at each agent also starts tours of the next
//! agent, one at a time, each round awaiting the next agent's counter,
//! counting here, sending it a message, sleeping and computing, while
//! leaders are stopped mid-await and mid-computation; its owner reads each
//! tour's result by its id. Every tour ends as a straight run ends it, or
//! fails on the record, and each of its effects applies once.
//!
//! The seed is printed; `EXACTLY_ONCE_SEED` runs one again.

use std::sync::atomic::{AtomicBool, Ordering};

use vos_checker::calls::install_at_leader;
use vos_checker::programs::{actor, package, schema};
use vos_checker::rounds::{ASKED, ROUNDS, Rounds, TOLD};
use vos_checker::{
    ANSWERED, COUNTER, Client, INBOX, Methods, Mode, Random, SECOND, Touring, check_tallies,
    wait_until,
};
use vos_node::Node;
use vos_wire::ids::{AgentId, InstanceId, MethodId};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, keys};

use crate::faults::faults;
use crate::harness::{Cluster, NODES, query};

/// Ends the clients and readers when the faults are over, or have failed:
/// they stop pausing, and stop.
struct Ending<'a>(&'a AtomicBool, &'a Cluster);

impl Drop for Ending<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
        self.1.paused.store(false, Ordering::SeqCst);
    }
}

/// Install the rounds actor at `agent` as the instance its tours start at,
/// and as those the previous agent's tours ask and tell.
fn install_rounds(cluster: &Cluster, agent: AgentId, rounds: &Rounds) {
    for instance in [ASKED, TOLD, ROUNDS] {
        install_at_leader(|| cluster.leading(agent), agent, instance, &rounds.elf);
    }
}

/// `node`'s tallies at `agent`'s rounds `instance`, checked against what
/// `touring`'s tours tallied there: how many amounts applied, each once.
pub(crate) fn tallied(
    node: &Node,
    agent: AgentId,
    instance: InstanceId,
    touring: &Touring,
) -> Result<u64, String> {
    let read = |method| match query(node, agent, instance, method) {
        Ok(Outcome::Done(bytes)) => Ok(bytes),
        other => Err(format!("{other:?}")),
    };
    let tallies = <Vec<(u64, u64)>>::decode(&read(touring.methods.tallies)?)
        .unwrap()
        .0;
    let total = u64::decode(&read(touring.methods.total)?).unwrap().0;
    check_tallies(touring, &tallies, total)
}

fn exactly_once(mode: Mode, default_seed: u64, rounds: Option<Rounds>) {
    let seed = std::env::var("EXACTLY_ONCE_SEED")
        .ok()
        .and_then(|seed| seed.parse().ok())
        .unwrap_or(default_seed);
    println!("seed {seed}");
    let mut random = Random::new(seed);
    let cluster = Cluster::new(seed);
    let methods = Methods::of(&schema(&actor("counter")));
    let agents = agents(&cluster, rounds.as_ref());
    // At each agent, one client forwarding to the next agent's inbox and a
    // second incrementing a counter of its own: batches mix their
    // sessions, new and held. With workflows, a third tours the next agent.
    let tours = rounds.as_ref().map(|rounds| rounds.methods);
    let count = if tours.is_some() { 9 } else { 6 };
    let clients = vos_checker::clients(&agents, count, methods, tours, |bound| random.below(bound));
    let at_each = agents.len();
    let forwarding = &clients[..at_each];
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
    let seen = cluster.log.seen();
    assert!(
        seen.contains_key("session timed again"),
        "no session met the clocks' jump"
    );
    if rounds.is_some() {
        for stop in [
            "fault: a leader stops mid-await",
            "fault: a leader stops mid-computation",
        ] {
            assert!(seen.contains_key(stop), "never: {stop}");
        }
    }
    // Healed, every replica holds every request once.
    cluster.hub.heal();
    for number in 1..=NODES {
        if cluster.node(number).is_none() {
            cluster.start(number);
        }
    }
    let (sent_forwarding, sent_second, sent_touring) = (
        &sent[..at_each],
        &sent[at_each..2 * at_each],
        &sent[2 * at_each..],
    );
    check_counters(
        &cluster,
        &clients[at_each..2 * at_each],
        sent_second,
        methods.value,
    );
    let touring = &clients[2 * at_each..];
    let toured = check_tours(&cluster, touring, sent_forwarding, sent_touring);
    check_forwards(
        &cluster,
        forwarding,
        sent_forwarding,
        &toured,
        methods.value,
    );
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

/// The run's agents, each created at a node of its own and replicated on
/// all three, with the counter installed as its inbox and its two
/// counters, and `rounds` as its tours' instances: each with its identity.
fn agents(cluster: &Cluster, rounds: Option<&Rounds>) -> Vec<(AgentId, [u8; 32])> {
    let counter = package("counter");
    (1..=3u8)
        .map(|number| {
            let creator = cluster.node(number).unwrap();
            let agent = creator.create_replicated(vec![1, 2, 3]).unwrap();
            // The inbox first: no message reaches an instance not there yet.
            for instance in [INBOX, COUNTER, SECOND] {
                install_at_leader(|| cluster.leading(agent), agent, instance, &counter);
            }
            if let Some(rounds) = rounds {
                install_rounds(cluster, agent, rounds);
            }
            (agent, cluster.identity(number, agent))
        })
        .collect()
}

/// Each counter of its own a client in `seconds` incremented holds every
/// request it sent, `sent`, at every replica.
fn check_counters(cluster: &Cluster, seconds: &[Client], sent: &[u64], value: MethodId) {
    for (client, &sent) in seconds.iter().zip(sent) {
        let total = client.total(sent);
        for number in 1..=NODES {
            let node = cluster.node(number).unwrap();
            wait_until("every replica converges", ANSWERED, || {
                query(&node, client.agent, client.instance, value)
                    == Ok(Outcome::Done(total.encode()))
            });
        }
    }
}

/// Each tour's effects applied once: the next agent's asked and told
/// rounds, and this agent's own, tally every amount of a tour that ended
/// done once, and of one that failed once or not at all; its requests and
/// messages went once, each request answered once. Every workflow started
/// once, and none lives on. `forwarded` are what each agent's forwarding
/// client sent, `started` the tours each touring client started. Answers
/// the tours' messages on each agent's pair with the next, by agent.
fn check_tours(
    cluster: &Cluster,
    touring: &[Client],
    forwarded: &[u64],
    started: &[u64],
) -> Vec<u64> {
    let mut messages = vec![0; forwarded.len()];
    for (at, client) in touring.iter().enumerate() {
        let tours = client.tours().unwrap();
        let (ended, failed) = tours.ended();
        println!(
            "client {}: {ended} tours ended as a straight run, {failed} failed",
            client.number
        );
        assert!(ended > 0, "client {} ended no tour", client.number);
        let (agent, next) = (client.agent, client.next_agent().unwrap());
        let forwards = forwarded[at] / 5;
        for number in 1..=NODES {
            let node = cluster.node(number).unwrap();
            let mark = |agent, key: &[u8]| vos_checker::mark(node.store(), agent, key);
            let mut checked = Err(String::new());
            wait_until("every replica holds every tour's effects", ANSWERED, || {
                checked = (|| {
                    tallied(&node, agent, ROUNDS, tours)?;
                    let asked = tallied(&node, next, ASKED, tours)?;
                    let told = tallied(&node, next, TOLD, tours)?;
                    let sent = mark(agent, &keys::pair_out(next));
                    let replies = mark(next, &keys::pair_out(agent));
                    let settled = mark(agent, &keys::live_workflows()) == 0
                        && sent == forwards + asked + told
                        && mark(next, &keys::pair_in(agent)) == sent
                        && replies == asked
                        && mark(agent, &keys::pair_in(next)) == replies;
                    settled
                        .then_some(asked + told)
                        .ok_or_else(|| format!("{asked} asked, {told} told, {sent} sent"))
                })();
                checked.is_ok()
            });
            let held = checked.unwrap();
            assert!(
                number == 1 || messages[at] == held,
                "client {}: replicas differ",
                client.number
            );
            messages[at] = held;
            assert_eq!(
                mark(agent, &keys::next_workflow()),
                started[at],
                "every tour started once"
            );
            let pins = keys::workflow_pins_prefix();
            assert_eq!(node.store().snapshot().scan(agent, &pins, None).count(), 0);
        }
    }
    messages
}

/// Each forwarding client's counter holds every request it sent, `sent`,
/// at every replica, and the next agent's inbox every forward; its pair
/// with the next agent sent and applied each forward, and each of
/// `toured`'s tours' messages, once, its outbox emptied.
fn check_forwards(
    cluster: &Cluster,
    forwarding: &[Client],
    sent: &[u64],
    toured: &[u64],
    value: MethodId,
) {
    for (at, client) in forwarding.iter().enumerate() {
        let total = client.total(sent[at]);
        let (next, next_agent) = (
            &forwarding[(at + 1) % forwarding.len()],
            client.next_agent().unwrap(),
        );
        let inbox = client.forwarded(sent[at]);
        // The forwards, and the tours' requests and messages, on one pair.
        let messages = sent[at] / 5 + toured[at];
        for number in 1..=NODES {
            let node = cluster.node(number).unwrap();
            let mark = |agent, key: &[u8]| vos_checker::mark(node.store(), agent, key);
            let counted = |agent, instance| query(&node, agent, instance, value);
            wait_until("every replica converges", ANSWERED, || {
                let acked = mark(client.agent, &keys::acked(next_agent));
                counted(client.agent, COUNTER) == Ok(Outcome::Done(total.encode()))
                    && counted(next_agent, INBOX) == Ok(Outcome::Done(inbox.encode()))
                    && acked == messages
                    && acked == mark(client.agent, &keys::pair_out(next_agent))
                    && node
                        .store()
                        .snapshot()
                        .scan(client.agent, &keys::outbox_prefix(), None)
                        .count()
                        == 0
            });
            // Each message applied once at the receiver, and was sent once.
            assert_eq!(
                mark(next.agent, &keys::pair_in(client.agent)),
                mark(client.agent, &keys::pair_out(next_agent))
            );
        }
    }
}

#[test]
fn one_request_at_a_time_applies_once_through_failures() {
    exactly_once(Mode::OneAtATime, 0x5eed_0001, None);
}

#[test]
fn pipelined_requests_apply_once_through_failures() {
    exactly_once(Mode::Pipelined, 0x5eed_0002, None);
}

#[test]
fn workflows_apply_once_through_failures() {
    exactly_once(Mode::OneAtATime, 0x5eed_0003, Some(Rounds::load()));
}
