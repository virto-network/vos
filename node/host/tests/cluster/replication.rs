//! Replicated agents on nodes in one process: creation and the directory,
//! calls at the leader applied on every replica alike, leader changes, a
//! partitioned follower catching up, restarts, and the programs each
//! replica holds.

use std::sync::Arc;
use std::time::Duration;

use vos_checker::calls::done;
use vos_checker::programs::actor;
use vos_node::store::EntryKind;
use vos_node::{CallError, Hooks, Node, Reply};
use vos_wire::Encode;
use vos_wire::abi::refusal;
use vos_wire::batch::{Batch, Input};
use vos_wire::ids::AgentId;
use vos_wire::ingress::{Answer, Call, Contact, NodeId};
use vos_wire::peer::{NodeNumber, PeerMessage};

use crate::common::{COUNTER, Cluster, WithholdBlobs, replaced, retired, wait_until};

#[test]
fn an_agent_created_on_three_nodes_applies_alike_on_each() {
    let cluster = Cluster::new(3);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    assert_eq!(agent.0 >> 24, 1, "an id from the creating node's range");
    let leader = cluster.leader(agent);
    for (sequence, by) in [(1u64, 5u64), (2, 7), (3, 1)] {
        assert_eq!(
            done(cluster.increment(leader, agent, sequence, by)),
            [5, 12, 13][sequence as usize - 1]
        );
    }
    cluster.converged(agent);
    for number in 1..=3 {
        assert_eq!(
            cluster.value(number, agent),
            13,
            "node {number} reads its replica"
        );
    }
    let pins: Vec<Vec<[u8; 32]>> = (1..=3)
        .map(|number| cluster.node(number).pinned())
        .collect();
    assert!(!pins[0].is_empty(), "the program is pinned");
    assert!(
        pins.windows(2).all(|pair| pair[0] == pair[1]),
        "pins differ"
    );
}

/// A call forwarded to a replica as its leader at a term it does not lead
/// at is answered with who leads, at what term, and does not run; sent
/// at the leader's term, it runs once.
#[test]
fn a_forward_at_another_term_is_answered_by_who_leads() {
    let mut cluster = Cluster::new(3);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.leader(agent);
    let term = cluster.node(leader).replica(agent).unwrap().term;
    // The test stands in for a follower.
    let follower = cluster.impersonate(leader % 3 + 1);
    let call = Call {
        session: cluster.session,
        sequence: 1,
        instance: COUNTER,
        method: cluster.programs.method("increment"),
        arguments: 5u64.encode(),
        signature: [0; 64],
    };
    let forward = |token: u64, term: u64| {
        let call = call.clone();
        follower.send(
            leader,
            &PeerMessage::Forward {
                agent,
                token,
                term,
                call,
            },
        );
        // Its answer, past the other requests the leader sends the node.
        follower.answer(|message| match message {
            PeerMessage::Forwarded {
                token: answered,
                term,
                answer,
                ..
            } if answered == token => Some((term, answer)),
            _ => None,
        })
    };
    // A copy held from an earlier term, or sent at a later one.
    for (token, at) in [(1, term - 1), (2, term + 1)] {
        let (answered_at, answer) = forward(token, at);
        assert_eq!(answered_at, term);
        let Answer::NotLeader {
            leader: Some(named),
        } = answer
        else {
            panic!("{answer:?}")
        };
        assert_eq!(named.node.0, cluster.space.node(leader).unwrap().key);
    }
    let (_, answer) = forward(3, term);
    assert!(matches!(answer, Answer::Ran { .. }), "{answer:?}");
    assert_eq!(cluster.value(leader, agent), 5, "it ran once");
}

#[test]
fn followers_and_other_nodes_send_callers_where_the_agent_is_served() {
    let cluster = Cluster::new(4);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let (leader, follower) = cluster.leader_and_follower(agent);
    let contact = |number: NodeNumber| Contact {
        address: format!("http://node-{number}"),
        node: NodeId(cluster.space.node(number).unwrap().key),
    };
    assert_eq!(
        cluster.increment(follower, agent, 1, 1),
        Err(CallError::NotLeader(Some(contact(leader))))
    );
    wait_until("node 4 learns of the agent", || {
        matches!(
            cluster.increment(4, agent, 1, 1),
            Err(CallError::Elsewhere(_))
        )
    });
    assert_eq!(
        cluster.increment(4, agent, 1, 1),
        Err(CallError::Elsewhere((1..=3).map(contact).collect()))
    );
}

#[test]
fn a_new_leader_serves_after_the_old_one_stops_and_the_old_one_catches_up() {
    let mut cluster = Cluster::new(3);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let first = cluster.leader(agent);
    assert_eq!(done(cluster.increment(first, agent, 1, 5)), 5);
    let time = |node: &Node| {
        node.store()
            .snapshot()
            .last_result(agent)
            .unwrap()
            .unwrap()
            .0
    };
    let before = time(cluster.node(first));
    cluster.stop(first);
    let second = cluster.leader(agent);
    assert_ne!(second, first);
    // Every node left names the new leader's placement, at its term.
    let term = cluster.node(second).replica(agent).unwrap().term;
    wait_until("every node names the new leader's placement", || {
        cluster.running().all(|(_, node)| {
            node.replica(agent)
                .is_some_and(|status| status.placement_term >= term)
        })
    });
    // The same session goes on at the new leader.
    assert_eq!(done(cluster.increment(second, agent, 2, 7)), 12);
    assert!(time(cluster.node(second)) >= before, "batch time went back");
    cluster.start(first);
    cluster.converged(agent);
    assert_eq!(cluster.value(first, agent), 12);
}

#[test]
fn a_partitioned_follower_catches_up_and_runs_the_program_it_missed() {
    let cluster = Cluster::new(3);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    let (leader, follower) = cluster.leader_and_follower(agent);
    wait_until("the follower runs the group", || {
        cluster.node(follower).applied(agent).is_some()
    });
    cluster.hub.isolate(follower);
    cluster.install(agent);
    assert_eq!(done(cluster.increment(leader, agent, 1, 3)), 3);
    assert!(cluster.node(follower).pinned().is_empty());
    cluster.hub.heal();
    cluster.converged(agent);
    assert_eq!(
        cluster.node(follower).pinned(),
        cluster.node(leader).pinned()
    );
    assert_eq!(cluster.value(follower, agent), 3);
}

#[test]
fn a_restarted_follower_recovers_its_group() {
    let mut cluster = Cluster::new(3);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let (leader, follower) = cluster.leader_and_follower(agent);
    assert_eq!(done(cluster.increment(leader, agent, 1, 2)), 2);
    cluster.converged(agent);
    cluster.stop(follower);
    assert_eq!(done(cluster.increment(leader, agent, 2, 3)), 5);
    cluster.start(follower);
    cluster.converged(agent);
    assert_eq!(cluster.value(follower, agent), 5);
}

#[test]
fn a_record_reaches_a_node_that_was_down_from_a_replica() {
    let mut cluster = Cluster::new(3);
    cluster.stop(3);
    // Nodes 1 and 2 are a majority: the creation is answered.
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    // The creator, and with it any leader it was, is lost before node 3
    // comes back. Node 2's group campaigns; node 3, sent its requests,
    // asks node 2 for the record, and the two are a majority.
    cluster.stop(1);
    cluster.start(3);
    let leader = cluster.leader(agent);
    cluster.install(agent);
    assert_eq!(done(cluster.increment(leader, agent, 1, 3)), 3);
    cluster.converged(agent);
    // The creator back: its re-announcement meets nodes that hold the
    // record, and it catches up.
    cluster.start(1);
    cluster.converged(agent);
    assert_eq!(cluster.value(1, agent), 3);
}

#[test]
fn a_replica_with_another_agent_program_refuses_the_group() {
    // Node 3 runs another program as its agent program.
    let counter = actor("counter");
    let cluster = Cluster::tuned(3, move |number, config| {
        if number == 3 {
            config.agent = counter.clone();
        }
    });
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    assert_ne!(leader, 3);
    assert_eq!(done(cluster.increment(leader, agent, 1, 4)), 4);
    assert!(
        cluster.node(3).applied(agent).is_none(),
        "node 3 runs no group"
    );
}

/// Fails the leader's dry run of a batch holding the poisoned argument.
struct PoisonDryRun(Vec<u8>);

impl Hooks for PoisonDryRun {
    fn fail_dry_run(&self, _: AgentId, batch: &Batch) -> bool {
        batch.inputs.iter().any(|input| match input {
            Input::Request(request) => request.arguments == self.0,
            _ => false,
        })
    }
}

#[test]
fn an_input_whose_accumulate_fails_is_isolated_before_the_log() {
    let poisoned = 666u64.encode();
    let poison = Arc::new(PoisonDryRun(poisoned.clone()));
    let cluster = Cluster::tuned(3, move |_, config| config.hooks = poison.clone());
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.leader(agent);
    let node = cluster.node(leader);
    // Queued together, they share a batch until it fails.
    let calls: Vec<_> = [(1u64, 1u64), (2, 666), (3, 2)]
        .into_iter()
        .map(|(sequence, by)| node.call(agent, cluster.request(sequence, by)))
        .collect();
    let replies: Vec<_> = calls.into_iter().map(smol::block_on).collect();
    assert_eq!(done(replies[0].clone()), 1);
    assert_eq!(replies[1], Ok(Reply::Failed));
    assert_eq!(replies[2], Ok(Reply::Refused(refusal::SEQUENCE)));
    cluster.converged(agent);
    // No entry carries the poisoned input.
    let store = node.store();
    let applied = node.applied(agent).unwrap();
    for index in 1..=applied {
        let entry = store.log_entry(agent, index).unwrap().unwrap();
        if entry.kind == EntryKind::Result {
            assert!(
                !entry
                    .body
                    .windows(poisoned.len())
                    .any(|window| window == poisoned),
                "entry {index} carries the poisoned input"
            );
        }
    }
}

#[test]
fn a_record_reaches_a_node_that_comes_up_later_while_its_creator_runs() {
    let mut cluster = Cluster::new(3);
    cluster.stop(3);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    cluster.start(3);
    wait_until("the creator's resends reach node 3", || {
        cluster.node(3).applied(agent).is_some()
    });
}

#[test]
fn three_nodes_over_quic_replicate_and_fail_over() {
    let mut cluster = Cluster::over_quic(3);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let first = cluster.leader(agent);
    assert_eq!(done(cluster.increment(first, agent, 1, 5)), 5);
    cluster.converged(agent);
    cluster.stop(first);
    let second = cluster.leader(agent);
    assert_eq!(done(cluster.increment(second, agent, 2, 6)), 11);
    cluster.start(first);
    cluster.converged(agent);
    assert_eq!(cluster.value(first, agent), 11);
}

/// Fails the apply of the first entry of each agent whose result carries
/// the marked bytes, on every replica alike (they apply the same entries).
struct FailFirstApply {
    mark: Vec<u8>,
    first: std::sync::Mutex<std::collections::HashMap<AgentId, u64>>,
}

impl Hooks for FailFirstApply {
    fn fail_apply(&self, agent: AgentId, index: u64, result: &[u8]) -> bool {
        if !result
            .windows(self.mark.len())
            .any(|window| window == self.mark)
        {
            return false;
        }
        let mut first = self.first.lock().unwrap();
        *first.entry(agent).or_insert(index) == index
    }
}

#[test]
fn a_result_that_applies_as_no_writes_is_retried_not_answered() {
    let by = 0x0102_0304_0506_0708u64;
    let hooks = Arc::new(FailFirstApply {
        mark: by.encode(),
        first: Default::default(),
    });
    let shared = Arc::clone(&hooks);
    let cluster = Cluster::tuned(3, move |_, config| config.hooks = shared.clone());
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.leader(agent);
    // The first entry carrying it applies as no writes everywhere; the
    // leader runs its inputs again rather than answer them.
    assert_eq!(done(cluster.increment(leader, agent, 1, by)), by);
    assert!(
        hooks.first.lock().unwrap().contains_key(&agent),
        "an apply failed"
    );
    cluster.converged(agent);
    for number in 1..=3 {
        assert_eq!(
            cluster.value(number, agent),
            by,
            "applied once, on node {number}"
        );
    }
}

#[test]
fn a_follower_fetches_a_blob_from_another_member_when_the_leader_withholds_it() {
    let hooks: Vec<Arc<WithholdBlobs>> = (0..3).map(|_| Arc::default()).collect();
    let each = hooks.clone();
    let cluster = Cluster::tuned(3, move |number, config| {
        config.hooks = each[usize::from(number) - 1].clone();
    });
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    let (leader, follower) = cluster.leader_and_follower(agent);
    wait_until("the follower runs the group", || {
        cluster.node(follower).applied(agent).is_some()
    });
    cluster.hub.isolate(follower);
    cluster.install(agent);
    assert_eq!(done(cluster.increment(leader, agent, 1, 3)), 3);
    // The leader no longer serves blobs: the follower must ask the other.
    hooks[usize::from(leader) - 1].withhold(true);
    cluster.hub.heal();
    cluster.converged(agent);
    assert_eq!(
        cluster.node(follower).pinned(),
        cluster.node(leader).pinned()
    );
    assert_eq!(cluster.value(follower, agent), 3);
}

/// A replica that never took an agent's install holds its program in the
/// pool once it runs it: a leader elected later at its first call, a
/// follower at its first query. Neither builds the program from its blob
/// at every run.
#[test]
fn replicas_that_never_took_the_install_pool_the_program_on_first_use() {
    let mut cluster = Cluster::new(3);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let first = cluster.leader(agent);
    let program = cluster.node(first).pinned()[0];
    assert!(cluster.node(first).pooled(&program), "the install pools it");
    wait_until("every replica pins the program", || {
        (1..=3).all(|number| cluster.node(number).pinned().contains(&program))
    });
    assert!(
        (1..=3)
            .filter(|number| *number != first)
            .all(|number| !cluster.node(number).pooled(&program))
    );

    cluster.stop(first);
    let second = cluster.leader(agent);
    assert!(!cluster.node(second).pooled(&program));
    assert_eq!(done(cluster.increment(second, agent, 1, 5)), 5);
    assert!(
        cluster.node(second).pooled(&program),
        "pooled at its first call"
    );

    let follower = (1..=3)
        .find(|number| *number != first && *number != second)
        .unwrap();
    assert!(!cluster.node(follower).pooled(&program));
    wait_until("the follower applies the call", || {
        cluster.node(follower).applied(agent) >= cluster.node(second).applied(agent)
    });
    assert_eq!(cluster.value(follower, agent), 5);
    assert!(
        cluster.node(follower).pooled(&program),
        "pooled at its first query"
    );
}

/// The pool drops a program once no agent on the node pins it, keeps one
/// another agent still pins, and holds it again once it is pinned and run
/// again. A restart leaves it as the pins do. The blob store, collected
/// every 100 ms, drops the program past its horizon (3 s) too, while the
/// nodes that pin it keep it.
#[test]
fn a_program_leaves_the_pool_with_its_last_pin() {
    let mut cluster = Cluster::tuned(4, |_, config| {
        config.blob_collect_every = Duration::from_millis(100);
        config.blob_horizon = Duration::from_secs(3);
    });
    let agents: Vec<AgentId> = (0..2).map(|_| cluster.counter_agent(&[1, 2, 3])).collect();
    let leaders: Vec<NodeNumber> = agents.iter().map(|agent| cluster.leader(*agent)).collect();
    let node = (1..=3).find(|number| !leaders.contains(number)).unwrap();
    let program = cluster.node(leaders[0]).pinned()[0];
    for agent in &agents {
        wait_until("the replica applies the install", || {
            cluster.node(node).applied(*agent)
                >= cluster.node(cluster.leader(*agent)).applied(*agent)
        });
        assert_eq!(cluster.value(node, *agent), 0);
    }
    assert!(cluster.node(node).pooled(&program));

    let replace = |agent: AgentId, leader: NodeNumber| {
        let replicas = replaced(&[1, 2, 3], node, 4);
        assert_eq!(
            cluster.node(leader).replace(agent, node, 4).unwrap(),
            replicas
        );
        cluster.placed(agent, &replicas);
        retired(cluster.node(node), agent);
    };
    replace(agents[0], leaders[0]);
    assert!(
        cluster.node(node).pooled(&program),
        "kept while another agent pins it"
    );
    replace(agents[1], leaders[1]);
    wait_until("the pool drops the program", || {
        !cluster.node(node).pooled(&program)
    });
    wait_until("the blob store drops the program", || {
        !cluster.node(node).stores_blob(&program)
    });
    std::thread::sleep(Duration::from_millis(500));
    for (number, running) in cluster.running() {
        if number != node {
            assert!(running.stores_blob(&program), "node {number} pins it");
        }
    }
    cluster.stop(node);
    cluster.start(node);
    assert!(
        !cluster.node(node).pooled(&program),
        "a restart pools no program unpinned"
    );

    let mut replicas: Vec<NodeNumber> = (1..=4)
        .filter(|number| *number != node)
        .take(2)
        .chain([node])
        .collect();
    replicas.sort_unstable();
    let third = cluster.counter_agent(&replicas);
    wait_until("the replica applies the install", || {
        cluster.node(node).applied(third) >= cluster.node(cluster.leader(third)).applied(third)
    });
    assert_eq!(cluster.value(node, third), 0);
    assert!(cluster.node(node).pooled(&program), "held again once run");
    assert!(cluster.node(node).stores_blob(&program), "fetched again");
    cluster.stop(node);
    cluster.start(node);
    assert!(
        cluster.node(node).pooled(&program),
        "a restart pools a program pinned"
    );
}
