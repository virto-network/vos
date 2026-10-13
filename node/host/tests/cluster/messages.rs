//! Messages between replicated agents on nodes in one process: each
//! applied once at its target and acknowledged, through the directory,
//! relays and leader changes, and checked at every hop.

use std::time::{Duration, Instant};

use vos_node::{CallError, Reply};
use vos_wire::abi::failure;
use vos_wire::batch::{Message, Request};
use vos_wire::ids::AgentId;
use vos_wire::keys;
use vos_wire::peer::{NodeNumber, PeerMessage};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};

use crate::common::{COUNTER, Cluster, wait_until};

impl Cluster {
    /// `from`'s forward of `by` to `to`'s counter, called at node `at`.
    fn forward(
        &self,
        at: NodeNumber,
        from: AgentId,
        sequence: u64,
        to: AgentId,
        by: u64,
    ) -> Result<Reply, CallError> {
        let request = Request {
            method: self.programs.method("forward"),
            arguments: (to.0, COUNTER.0, by).encode(),
            ..self.request(sequence, by)
        };
        smol::block_on(self.node(at).call(from, request))
    }

    /// Forward `by` from `from` to `to`, at whichever node leads `from`,
    /// until it is answered.
    fn forward_once(&self, from: AgentId, sequence: u64, to: AgentId, by: u64) {
        wait_until("a forward is answered", || {
            let leader = self.leader(from);
            matches!(
                self.forward(leader, from, sequence, to, by),
                Ok(Reply::Ran(Outcome::Done(_)))
            )
        });
    }

    /// The entries `agent`'s outbox holds at node `at`.
    fn outbox(&self, at: NodeNumber, agent: AgentId) -> usize {
        self.node(at)
            .store()
            .snapshot()
            .scan(agent, &keys::outbox_prefix(), None)
            .count()
    }

    /// `to`'s counter is `total` at every running replica in `replicas`,
    /// and `from`'s outbox is empty at every running replica of it.
    fn delivered(&self, from: (AgentId, &[NodeNumber]), to: (AgentId, &[NodeNumber]), total: u64) {
        wait_until("every message is applied once and acknowledged", || {
            self.running()
                .filter(|(number, _)| to.1.contains(number))
                .all(|(number, _)| self.value(number, to.0) == total)
                && self
                    .running()
                    .filter(|(number, _)| from.1.contains(number))
                    .all(|(number, _)| self.outbox(number, from.0) == 0)
        });
    }
}

/// A message to an agent on nodes the sender's node does not replicate
/// goes through the directory to one of them, which relays it to its
/// leader; it applies once, and its acknowledgement comes back.
#[test]
fn a_message_reaches_an_agent_on_other_nodes_once() {
    let cluster = Cluster::new(3);
    let sender = cluster.counter_agent(&[1]);
    let target = cluster.counter_agent(&[2, 3]);
    for (sequence, by) in [(1, 5), (2, 7)] {
        cluster.forward_once(sender, sequence, target, by);
    }
    cluster.delivered((sender, &[1]), (target, &[2, 3]), 12);
    assert!(cluster.node(1).messages_sent_across() > 0);
}

/// With the sender on {1, 2, 3} and the target on {2, 3, 4}, a message
/// goes to the target's leader from a replica of both, or through the
/// directory and a relay from node 1.
#[test]
fn messages_cross_overlapping_replica_sets() {
    let cluster = Cluster::new(4);
    let sender = cluster.counter_agent(&[1, 2, 3]);
    let target = cluster.counter_agent(&[2, 3, 4]);
    let mut total = 0;
    for sequence in 1..=6 {
        cluster.forward_once(sender, sequence, target, sequence);
        total += sequence;
    }
    cluster.delivered((sender, &[1, 2, 3]), (target, &[2, 3, 4]), total);
}

/// The target's leader stops with messages in flight: the sender's
/// rounds deliver them to the next, once.
#[test]
fn a_receivers_leader_stopping_loses_no_message() {
    let mut cluster = Cluster::new(3);
    let sender = cluster.counter_agent(&[1]);
    let target = cluster.counter_agent(&[2, 3]);
    for sequence in 1..=4 {
        cluster.forward_once(sender, sequence, target, 10);
    }
    let leader = cluster.leader(target);
    cluster.stop(leader);
    for sequence in 5..=8 {
        cluster.forward_once(sender, sequence, target, 10);
    }
    cluster.start(leader);
    cluster.delivered((sender, &[1]), (target, &[2, 3]), 80);
}

/// The sender's leader stops with its outbox unacknowledged: the next
/// leader delivers what it holds, once.
#[test]
fn a_senders_leader_stopping_loses_no_message() {
    let mut cluster = Cluster::new(4);
    let sender = cluster.counter_agent(&[1, 2, 3]);
    let target = cluster.counter_agent(&[4]);
    // The target is down: the messages wait in the sender's outbox.
    cluster.stop(4);
    for sequence in 1..=3 {
        cluster.forward_once(sender, sequence, target, 3);
    }
    let leader = cluster.leader(sender);
    cluster.stop(leader);
    cluster.start(4);
    cluster.leader(sender);
    cluster.start(leader);
    cluster.delivered((sender, &[1, 2, 3]), (target, &[4]), 9);
}

/// A backlog larger than a window drains, driven by acknowledgements.
#[test]
fn a_backlog_beyond_a_window_drains() {
    let mut cluster = Cluster::new(3);
    let sender = cluster.counter_agent(&[1]);
    let target = cluster.counter_agent(&[2, 3]);
    cluster.stop(2);
    cluster.stop(3);
    for sequence in 1..=300 {
        cluster.forward_once(sender, sequence, target, 1);
    }
    cluster.start(2);
    cluster.start(3);
    let until = Instant::now() + Duration::from_secs(60);
    loop {
        match cluster.query_value(2, target) {
            Ok(Outcome::Done(bytes)) if u64::decode(&bytes).unwrap().0 >= 300 => break,
            // Not caught up yet: the count so far, or no instance yet; a
            // replica still catching up after a restart may not hold it.
            Ok(Outcome::Done(_))
            | Ok(Outcome::Failed {
                code: failure::UNKNOWN,
                ..
            }) => {}
            other => panic!("{other:?}"),
        }
        assert!(Instant::now() < until, "the backlog did not drain");
        std::thread::sleep(Duration::from_millis(20));
    }
    cluster.delivered((sender, &[1]), (target, &[2, 3]), 300);
}

/// A message's hop is checked: one from a node that replicates neither
/// the sender nor the target is dropped.
#[test]
fn a_message_from_a_node_replicating_neither_end_is_dropped() {
    let mut cluster = Cluster::new(4);
    let sender = cluster.counter_agent(&[1, 2, 3]);
    let target = cluster.counter_agent(&[1, 2, 3]);
    let forger = cluster.impersonate(4);
    let leader = cluster.leader(target);
    for relayed in [false, true] {
        forger.send(
            leader,
            &PeerMessage::Deliver {
                to: target,
                message: Message {
                    from: sender,
                    sequence: 1,
                    instance: COUNTER,
                    method: cluster.programs.method("increment"),
                    arguments: 9u64.encode(),
                },
                relayed,
            },
        );
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(cluster.value(leader, target), 0, "a forged message ran");
}

/// A replica that does not lead relays a message to its leader: node 1's
/// first window goes through the target's replica its turn picks, node 3,
/// made a follower here.
#[test]
fn a_follower_relays_a_message_to_its_leader() {
    let mut cluster = Cluster::new(4);
    let sender = cluster.counter_agent(&[1]);
    let target = cluster.counter_agent(&[2, 3, 4]);
    if cluster.leader(target) == 3 {
        cluster.stop(3);
        wait_until("another leads", || {
            cluster.running().any(|(_, node)| node.leads(target))
        });
        cluster.start(3);
    }
    let leader = cluster.leader(target);
    assert_ne!(leader, 3);
    // Caught up, node 3 follows the leader, and knows where to relay.
    wait_until("node 3 follows", || {
        cluster.node(3).applied(target).is_some()
            && cluster.node(3).applied(target) == cluster.node(leader).applied(target)
    });
    cluster.forward_once(sender, 1, target, 11);
    cluster.delivered((sender, &[1]), (target, &[2, 3, 4]), 11);
    assert!(
        cluster.node(3).messages_relayed() > 0,
        "node 3 relayed nothing"
    );
}
