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
//! With workflows, a client at each agent also starts tours of the next
//! agent, one at a time, each round awaiting the next agent's counter,
//! counting here, sending it a message, sleeping and computing, while
//! leaders are stopped mid-await and mid-computation; its owner reads each
//! tour's result by its id. Every tour ends as a straight run ends it, or
//! fails on the record, and each of its effects applies once.
//!
//! The seed is printed; `EXACTLY_ONCE_SEED` runs one again.

use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use vos_checker::calls::install_at_leader;
use vos_checker::programs::{actor, method, package};
use vos_checker::rounds::{ASKED, ROUNDS, Rounds, TOLD};
use vos_checker::{
    COUNTER, Client, INBOX, Methods, Mode, Random, SECOND, Touring, check_tallies, wait_until,
};
use vos_node::Node;
use vos_wire::ids::{AgentId, InstanceId};
use vos_wire::records::unstored;
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

fn exactly_once(mode: Mode, default_seed: u64, workflows: bool) {
    let seed = std::env::var("EXACTLY_ONCE_SEED")
        .ok()
        .and_then(|seed| seed.parse().ok())
        .unwrap_or(default_seed);
    println!("seed {seed}");
    let mut random = Random(seed | 1);
    let cluster = Cluster::new(seed);
    let (program, counter) = (actor("counter"), package("counter"));
    let methods = Methods {
        increment: method(&program, "increment"),
        value: method(&program, "value"),
        forward: method(&program, "forward"),
    };
    let value = methods.value;
    let rounds = workflows.then(Rounds::load);
    let agents: Vec<(AgentId, [u8; 32])> = (1..=3u8)
        .map(|number| {
            let creator = cluster.node(number).unwrap();
            let agent = creator.create_replicated(vec![1, 2, 3]).unwrap();
            // The inbox first: no message reaches an instance not there yet.
            for instance in [INBOX, COUNTER, SECOND] {
                install_at_leader(|| cluster.leading(agent), agent, instance, &counter);
            }
            if let Some(rounds) = &rounds {
                install_rounds(&cluster, agent, rounds);
            }
            (agent, cluster.identity(number, agent))
        })
        .collect();
    // At each agent, one client forwarding to the next agent's inbox and a
    // second incrementing a counter of its own: batches mix their
    // sessions, new and held. With workflows, a third tours the next agent.
    let tours = rounds.as_ref().map(|rounds| rounds.methods);
    let count = if workflows { 9 } else { 6 };
    let clients: Vec<Client> = (1..=count)
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
            match tours {
                Some(tours) if number > 6 => {
                    Client::touring(number, agent, identity, methods, tours, rotate)
                }
                _ => Client::new(number, agent, identity, methods, forwarding, rotate),
            }
        })
        .collect();
    let forwarding = &clients[..agents.len()];
    let touring = &clients[2 * agents.len()..];
    for (at, client) in forwarding.iter().chain(touring).enumerate() {
        client.forward_to(agents[(at + 1) % agents.len()].0);
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
    let seen = cluster.log.seen();
    assert!(
        seen.contains_key("session timed again"),
        "no session met the clocks' jump"
    );
    if workflows {
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
    for (at, client) in clients
        .iter()
        .enumerate()
        .skip(forwarding.len())
        .take(agents.len())
    {
        let total = client.total(sent[at]);
        for number in 1..=NODES {
            let node = cluster.node(number).unwrap();
            wait_until("every replica converges", Duration::from_secs(60), || {
                counted(&node, client.agent, client.instance) == Ok(Outcome::Done(total.encode()))
            });
        }
    }
    // Each tour's effects applied once: the next agent's asked and told
    // rounds, and this agent's own, tally every amount of a tour that ended
    // done once, and of one that failed once or not at all; its requests
    // and messages went once, each request answered once. Every workflow
    // started once, and none lives on.
    let mut toured = vec![0; agents.len()];
    for (at, client) in touring.iter().enumerate() {
        let touring = client.tours().unwrap();
        let (ended, failed) = touring.ended();
        println!(
            "client {}: {ended} tours ended as a straight run, {failed} failed",
            client.number
        );
        assert!(ended > 0, "client {} ended no tour", client.number);
        let (agent, next) = (client.agent, client.next_agent().unwrap());
        let forwards = sent[at] / 5;
        for number in 1..=NODES {
            let node = cluster.node(number).unwrap();
            let mut checked = Err(String::new());
            wait_until(
                "every replica holds every tour's effects",
                Duration::from_secs(60),
                || {
                    checked = (|| {
                        tallied(&node, agent, ROUNDS, touring)?;
                        let asked = tallied(&node, next, ASKED, touring)?;
                        let told = tallied(&node, next, TOLD, touring)?;
                        let sent = mark(&node, agent, &keys::pair_out(next));
                        let replies = mark(&node, next, &keys::pair_out(agent));
                        let settled = mark(&node, agent, &keys::live_workflows()) == 0
                            && sent == forwards + asked + told
                            && mark(&node, next, &keys::pair_in(agent)) == sent
                            && replies == asked
                            && mark(&node, agent, &keys::pair_in(next)) == replies;
                        settled
                            .then_some(asked + told)
                            .ok_or_else(|| format!("{asked} asked, {told} told, {sent} sent"))
                    })();
                    checked.is_ok()
                },
            );
            let messages = checked.unwrap();
            assert!(
                number == 1 || toured[at] == messages,
                "client {}: replicas differ",
                client.number
            );
            toured[at] = messages;
            assert_eq!(
                mark(&node, agent, &keys::next_workflow()),
                sent[2 * agents.len() + at],
                "every tour started once"
            );
            let pins = keys::workflow_pins_prefix();
            assert_eq!(node.store().snapshot().scan(agent, &pins, None).count(), 0);
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
        // The forwards, and the tours' requests and messages, on one pair.
        let messages = forwards + toured[at];
        for number in 1..=NODES {
            let node = cluster.node(number).unwrap();
            wait_until("every replica converges", Duration::from_secs(60), || {
                let acked = mark(&node, client.agent, &keys::acked(next_agent));
                counted(&node, client.agent, COUNTER) == Ok(Outcome::Done(total.encode()))
                    && counted(&node, next_agent, INBOX) == Ok(Outcome::Done(inbox.encode()))
                    && acked == messages
                    && acked == mark(&node, client.agent, &keys::pair_out(next_agent))
                    && node
                        .store()
                        .snapshot()
                        .scan(client.agent, &keys::outbox_prefix(), None)
                        .count()
                        == 0
            });
            // Each message applied once at the receiver, and was sent once.
            assert_eq!(
                mark(&node, next.agent, &keys::pair_in(client.agent)),
                mark(&node, client.agent, &keys::pair_out(next_agent))
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
    exactly_once(Mode::OneAtATime, 0x5eed_0001, false);
}

#[test]
fn pipelined_requests_apply_once_through_failures() {
    exactly_once(Mode::Pipelined, 0x5eed_0002, false);
}

#[test]
fn workflows_apply_once_through_failures() {
    exactly_once(Mode::OneAtATime, 0x5eed_0003, true);
}
