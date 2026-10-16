//! Messages between replicated agents on nodes in one process: each
//! applied once at its target and acknowledged, through the directory,
//! relays and leader changes, and checked at every hop; a request answered
//! by a reply, a message the agent program fails on consumed as failed,
//! and a gap, or drops at a full queue once it drained, sent again at the
//! receiver's word.

use std::ops::RangeInclusive;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use vos_checker::hooks::{Holds, carries};
use vos_net::Class;
use vos_node::peer::Refusal;
use vos_node::store::EntryKind;
use vos_node::{CallError, Hooks, Reply};
use vos_wire::abi::Failure;
use vos_wire::batch::{Answer, Await, Batch, Body, Message};
use vos_wire::ids::{AgentId, WorkflowId};
use vos_wire::keys;
use vos_wire::peer::{NodeNumber, PeerMessage};
use vos_wire::result::{InputRef, Outcome, Run, Step, WorkResult};
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
        let forward = self.programs.method("forward");
        let request = self.request_of(sequence, forward, (to.0, COUNTER.0, by).encode());
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

    /// A value of `agent`'s applied state at node `at`.
    fn read<T: Decode>(&self, at: NodeNumber, agent: AgentId, key: &[u8]) -> Option<T> {
        vos_checker::applied(self.node(at).store(), agent, key)
    }

    /// The runs of the steps `agent` applied at node `at` for `input`.
    fn runs(&self, at: NodeNumber, agent: AgentId, input: &InputRef) -> Vec<Run> {
        let node = self.node(at);
        (1..=node.applied(agent).unwrap_or(0))
            .filter_map(|index| node.store().log_entry(agent, index).unwrap())
            .filter(|entry| entry.kind == EntryKind::Result)
            .flat_map(|entry| WorkResult::decode(&entry.body).unwrap().0.steps)
            .filter_map(|step| match step {
                Step::Ran(run) if run.input == *input => Some(run),
                _ => None,
            })
            .collect()
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
                code: Failure::Unknown,
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
                    body: Body::Call {
                        instance: COUNTER,
                        method: cluster.programs.method("increment"),
                        arguments: 9u64.encode(),
                        awaiting: None,
                    },
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

/// Fails the refine of every batch holding an input, a request or a
/// message, that calls with the poisoned arguments, as the agent program
/// failing on it would, and counts them.
struct PoisonedMessage {
    poison: Vec<u8>,
    failed: AtomicU64,
}

impl Hooks for PoisonedMessage {
    fn fail_refine(&self, _: AgentId, batch: &Batch) -> bool {
        let poisoned = carries(batch, &self.poison);
        if poisoned {
            self.failed.fetch_add(1, Ordering::SeqCst);
        }
        poisoned
    }
}

/// A message the agent program fails on alone, twice, is consumed as
/// failed: applied once, without running, acknowledged, and never sent
/// again. The pair goes on past it.
#[test]
fn a_message_failing_refine_is_consumed_once_and_never_sent_again() {
    let hook = Arc::new(PoisonedMessage {
        poison: 666u64.encode(),
        failed: AtomicU64::new(0),
    });
    let cluster = Cluster::hooked(3, hook.clone());
    let sender = cluster.counter_agent(&[1]);
    let target = cluster.counter_agent(&[2, 3]);
    cluster.forward_once(sender, 1, target, 666);
    cluster.delivered((sender, &[1]), (target, &[2, 3]), 0);
    assert!(
        hook.failed.load(Ordering::SeqCst) >= 2,
        "it failed alone twice"
    );
    let leader = cluster.leader(target);
    let input = InputRef::Message {
        from: sender,
        sequence: 1,
    };
    let runs = cluster.runs(leader, target, &input);
    assert_eq!(runs.len(), 1, "applied once");
    assert_eq!(
        runs[0].outcome,
        Outcome::Failed {
            code: Failure::InRefine,
            detail: vec![],
        }
    );
    assert_eq!(
        cluster.read::<u64>(1, sender, &keys::acked(target)),
        Some(1)
    );

    // Past two rounds, nothing went again.
    let failed = hook.failed.load(Ordering::SeqCst);
    let sent = cluster.node(1).messages_sent_across();
    std::thread::sleep(Duration::from_millis(3_500));
    assert_eq!(hook.failed.load(Ordering::SeqCst), failed);
    assert_eq!(cluster.node(1).messages_sent_across(), sent);

    cluster.forward_once(sender, 2, target, 3);
    cluster.delivered((sender, &[1]), (target, &[2, 3]), 3);
}

/// A message lost on its way leaves a gap, which the receiver refuses and
/// answers with `Behind`: the sender sends again at once, long before its
/// next round.
#[test]
fn a_gap_is_filled_within_a_round_trip() {
    let round = Duration::from_secs(20);
    let cluster = Cluster::tuned(2, move |_, config| config.resend_round = round);
    let sender = cluster.counter_agent(&[1]);
    let target = cluster.counter_agent(&[2]);
    cluster.forward_once(sender, 1, target, 1);
    cluster.delivered((sender, &[1]), (target, &[2]), 1);
    cluster.hub.cut_class(1, 2, Class::Requests);
    cluster.forward_once(sender, 2, target, 10);
    // Sent, and lost.
    std::thread::sleep(Duration::from_millis(200));
    cluster.hub.heal();
    let started = Instant::now();
    cluster.forward_once(sender, 3, target, 100);
    cluster.delivered((sender, &[1]), (target, &[2]), 111);
    let took = started.elapsed();
    assert!(
        took < Duration::from_secs(5),
        "the gap took {took:?}, waiting for a round of {round:?}"
    );
}

/// Two nodes with a resend round of `ROUND`, the second's queues capped at
/// `queue` and its refines held while `hold.refines` is closed.
fn held_receiver(queue: usize, hold: &Arc<Holds>) -> Cluster {
    let hold = Arc::clone(hold);
    Cluster::tuned(2, move |number, config| {
        config.resend_round = ROUND;
        if number == 2 {
            config.queue = queue;
            config.hooks = hold.clone();
        }
    })
}

/// A resend round no test waits for.
const ROUND: Duration = Duration::from_secs(20);

/// Raises its flag when dropped, so a thread looping until the flag ends
/// however the test does: a failed wait fails the test rather than leaving
/// its scope waiting on the loop.
struct Stopping<'a>(&'a AtomicBool);

impl Drop for Stopping<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// `sender`'s forwards of 1 to `target` at `sequences` of the cluster's
/// session, called at node 1 together and answered.
fn forwarded(cluster: &Cluster, sender: AgentId, target: AgentId, sequences: RangeInclusive<u64>) {
    let forwards: Vec<_> = sequences
        .map(|sequence| {
            let forward = cluster.programs.method("forward");
            let request =
                cluster.request_of(sequence, forward, (target.0, COUNTER.0, 1u64).encode());
            cluster.node(1).call(sender, request)
        })
        .collect();
    for forward in forwards {
        assert!(matches!(
            smol::block_on(forward),
            Ok(Reply::Ran(Outcome::Done(_)))
        ));
    }
}

/// Messages dropped at the receiver's full queue, with none after them to
/// leave a gap, are sent again once the queue drained: the receiver tells
/// their sender it is behind, long before its next round.
#[test]
fn a_full_queues_drops_go_again_once_it_drained() {
    let hold = Arc::new(Holds::default());
    let cluster = held_receiver(2, &hold);
    let sender = cluster.counter_agent(&[1]);
    let target = cluster.counter_agent(&[2]);
    cluster.forward_once(sender, 1, target, 1);
    cluster.delivered((sender, &[1]), (target, &[2]), 1);
    let closed = hold.refines.close();
    forwarded(&cluster, sender, target, 2..=11);
    wait_until("the receiver's full queue drops some", || {
        hold.refines.reached() > 0 && cluster.node(2).dropped(Refusal::Full) > 0
    });
    let released = Instant::now();
    drop(closed);
    cluster.delivered((sender, &[1]), (target, &[2]), 11);
    let took = released.elapsed();
    assert!(
        took < Duration::from_secs(5),
        "the drops took {took:?}, waiting for a round of {ROUND:?}"
    );
}

/// While another agent sends steadily, so the receiver's queue is seldom
/// empty, the senders whose windows it dropped full are told they are
/// behind as soon as it has room for them.
#[test]
fn a_full_queues_drops_go_again_beside_a_steady_sender() {
    const LAST: u64 = 301;
    let hold = Arc::new(Holds::default());
    let cluster = held_receiver(300, &hold);
    let steady = cluster.counter_agent(&[1]);
    let bulk = [cluster.counter_agent(&[1]), cluster.counter_agent(&[1])];
    let target = cluster.counter_agent(&[2]);
    for sender in [steady, bulk[0], bulk[1]] {
        cluster.forward_once(sender, 1, target, 1);
    }
    cluster.delivered((steady, &[1]), (target, &[2]), 3);
    let closed = hold.refines.close();
    std::thread::scope(|scope| {
        for sender in bulk {
            let cluster = &cluster;
            scope.spawn(move || forwarded(cluster, sender, target, 2..=LAST));
        }
    });
    wait_until("the receiver's full queue drops some", || {
        hold.refines.reached() > 0 && cluster.node(2).dropped(Refusal::Full) > 0
    });
    let stop = AtomicBool::new(false);
    std::thread::scope(|scope| {
        let stopping = Stopping(&stop);
        scope.spawn(|| {
            let mut sequence = 2;
            while !stop.load(Ordering::SeqCst) {
                forwarded(&cluster, steady, target, sequence..=sequence + 7);
                sequence += 8;
            }
        });
        let released = Instant::now();
        drop(closed);
        wait_until("every bulk message applies", || {
            bulk.iter()
                .all(|sender| cluster.read::<u64>(2, target, &keys::pair_in(*sender)) == Some(LAST))
        });
        drop(stopping);
        let took = released.elapsed();
        assert!(
            took < Duration::from_secs(5),
            "the drops took {took:?}, waiting for a round of {ROUND:?}"
        );
    });
}

/// A stale `Behind`, from a replica of the receiver, only sends again what
/// the receiver holds already: it drops the copies at its mark, and
/// nothing applies twice.
#[test]
fn a_stale_behind_changes_nothing() {
    let mut cluster = Cluster::new(4);
    let sender = cluster.counter_agent(&[1]);
    let target = cluster.counter_agent(&[2, 3, 4]);
    for (sequence, by) in [(1, 1), (2, 2)] {
        cluster.forward_once(sender, sequence, target, by);
    }
    cluster.delivered((sender, &[1]), (target, &[2, 3, 4]), 3);
    let replica = cluster.impersonate(4);
    // The target applies the next two, but its acknowledgements are lost:
    // the sender's window holds them.
    cluster.hub.cut_class(2, 1, Class::Requests);
    cluster.hub.cut_class(3, 1, Class::Requests);
    for (sequence, by) in [(3, 4), (4, 8)] {
        cluster.forward_once(sender, sequence, target, by);
    }
    wait_until("the target applies both, unacknowledged", || {
        cluster.value(cluster.leader(target), target) == 15 && cluster.outbox(1, sender) == 2
    });
    let sent = cluster.node(1).messages_sent_across();
    replica.send(
        1,
        &PeerMessage::Behind {
            sender,
            receiver: target,
            relayed: false,
        },
    );
    wait_until("the sender sends its window again", || {
        cluster.node(1).messages_sent_across() >= sent + 2
    });
    std::thread::sleep(Duration::from_millis(200));
    let leader = cluster.leader(target);
    assert_eq!(cluster.value(leader, target), 15, "a copy applied");
    cluster.hub.heal();
    cluster.delivered((sender, &[1]), (target, &[2, 3]), 15);
    for at in [2, 3] {
        assert_eq!(
            cluster.read::<u64>(at, target, &keys::pair_in(sender)),
            Some(4)
        );
    }
}

/// A call from `sender` to `target`'s counter adding `by`, at `sequence`
/// of their pair, awaited by workflow 7's await `counter`.
fn request(cluster: &Cluster, sender: AgentId, sequence: u64, by: u64) -> Message {
    Message {
        from: sender,
        sequence,
        body: Body::Call {
            instance: COUNTER,
            method: cluster.programs.method("increment"),
            arguments: by.encode(),
            awaiting: Some(awaiting(sequence)),
        },
    }
}

fn awaiting(counter: u64) -> Await {
    Await {
        workflow: WorkflowId(7),
        counter,
    }
}

/// `target`'s reply to `sender`'s request at `sequence` holds `answer`, in
/// the run that applied the request at node `at`.
fn replied(
    cluster: &Cluster,
    at: NodeNumber,
    (sender, target): (AgentId, AgentId),
    sequence: u64,
    answer: Answer,
) {
    let input = InputRef::Message {
        from: sender,
        sequence,
    };
    let runs = cluster.runs(at, target, &input);
    assert_eq!(runs.len(), 1);
    let replies: Vec<_> = runs[0]
        .messages
        .iter()
        .map(|outgoing| (outgoing.to, outgoing.body.clone()))
        .collect();
    let reply = Body::Reply {
        awaiting: awaiting(sequence),
        answer,
    };
    assert_eq!(replies, [(sender, reply)]);
}

/// The requester consumed the reply at `sequence` once, at node `at`, and
/// the replier's outbox emptied at every running replica of `replicas`.
fn consumed(
    cluster: &Cluster,
    at: NodeNumber,
    (sender, target): (AgentId, AgentId),
    replicas: &[NodeNumber],
    sequence: u64,
) {
    wait_until("the reply is consumed and acknowledged", || {
        cluster.read::<u64>(at, sender, &keys::pair_in(target)) == Some(sequence)
            && cluster
                .running()
                .filter(|(number, _)| replicas.contains(number))
                .all(|(number, _)| cluster.outbox(number, target) == 0)
    });
    let input = InputRef::Message {
        from: target,
        sequence,
    };
    let runs = cluster.runs(at, sender, &input);
    assert_eq!(runs.len(), 1, "consumed once");
    assert_eq!(runs[0].outcome, Outcome::Done(vec![]));
}

/// A request from an agent on another node is answered by a reply on the
/// reverse pair, which its sender consumes and acknowledges.
#[test]
fn a_request_is_answered_by_a_reply_across_nodes() {
    let cluster = Cluster::new(3);
    let sender = cluster.counter_agent(&[1]);
    let target = cluster.counter_agent(&[2, 3]);
    let leader = cluster.leader(target);
    cluster
        .node(leader)
        .deliver(target, request(&cluster, sender, 1, 5))
        .unwrap();
    consumed(&cluster, 1, (sender, target), &[2, 3], 1);
    replied(
        &cluster,
        leader,
        (sender, target),
        1,
        Answer::Done(5u64.encode()),
    );
    assert_eq!(cluster.value(leader, target), 5);
}

/// The replying agent's leader stops with its reply unsent, its requester
/// down: the next leader sends the reply from its outbox, once the
/// requester is back, and it is consumed once.
#[test]
fn a_reply_outlives_its_leader_stopping() {
    let mut cluster = Cluster::new(4);
    let sender = cluster.counter_agent(&[1]);
    let target = cluster.counter_agent(&[2, 3, 4]);
    cluster.stop(1);
    let leader = cluster.leader(target);
    cluster
        .node(leader)
        .deliver(target, request(&cluster, sender, 1, 9))
        .unwrap();
    wait_until("the request applies, its reply unsent", || {
        cluster.value(leader, target) == 9 && cluster.outbox(leader, target) == 1
    });
    replied(
        &cluster,
        leader,
        (sender, target),
        1,
        Answer::Done(9u64.encode()),
    );
    cluster.stop(leader);
    let next = cluster.leader(target);
    assert_ne!(next, leader);
    cluster.start(1);
    let replicas: Vec<NodeNumber> = [2, 3, 4].into_iter().filter(|n| *n != leader).collect();
    consumed(&cluster, 1, (sender, target), &replicas, 1);
    cluster.start(leader);
    cluster.delivered((sender, &[1]), (target, &[2, 3, 4]), 9);
}
