//! Replicas replaced on nodes in one process: a group's configuration
//! changing under load, across leader changes, partitions and crashes,
//! and the replica it removes retiring for good.

use std::time::Duration;

use vos_checker::calls::done;
use vos_checker::programs::actor;
use vos_node::store::{Fjall, PersistMode};
use vos_wire::ingress::Unplaced;
use vos_wire::peer::{NodeNumber, PeerMessage};

use crate::common::{Cluster, compacting, log_start, replaced, retired, wait_until};

/// One replica replaced by another node while calls go on: the new one
/// catches up, every node holds the new placement, the old replica keeps
/// nothing and does not come back after a restart.
#[test]
fn a_replica_is_replaced_under_load() {
    let mut cluster = Cluster::tuned(4, compacting);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let (leader, removed) = cluster.leader_and_follower(agent);
    cluster.increments(leader, agent, 1..=30);
    let replicas = replaced(&[1, 2, 3], removed, 4);
    let total = std::thread::scope(|scope| {
        let cluster = &cluster;
        let calls = scope.spawn(move || cluster.increments(leader, agent, 31..=60));
        assert_eq!(
            cluster.node(leader).replace(agent, removed, 4).unwrap(),
            replicas
        );
        calls.join().unwrap()
    });
    cluster.placed(agent, &replicas);
    retired(cluster.node(removed), agent);
    cluster.converged(agent);
    assert_eq!(cluster.value(4, agent), total);
    cluster.stop(removed);
    cluster.start(removed);
    std::thread::sleep(Duration::from_millis(300));
    assert!(cluster.node(removed).applied(agent).is_none());
    // Clients learn the replicas from any node.
    let info = cluster
        .node(removed)
        .placement(agent)
        .expect("the placement");
    assert_eq!(info.replicas, replicas);
}

/// After a replacement, the group compacts its log again and takes the
/// next change, though the replica it removed retired without
/// acknowledging the change to the group. Here the leader removes itself,
/// then its successor replaces another replica.
#[test]
fn a_replacement_leaves_the_group_free_to_change_and_compact() {
    let cluster = Cluster::tuned(5, compacting);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.leader(agent);
    cluster.increments(leader, agent, 1..=10);
    let replicas = replaced(&[1, 2, 3], leader, 4);
    assert_eq!(
        cluster.node(leader).replace(agent, leader, 4).unwrap(),
        replicas
    );
    retired(cluster.node(leader), agent);
    let next = cluster.leader(agent);
    let start = log_start(cluster.node(next), agent);
    cluster.increments(next, agent, 11..=40);
    assert!(
        log_start(cluster.node(next), agent) > start,
        "compacting again"
    );
    let removed = *replicas.iter().find(|number| **number != next).unwrap();
    let after = replaced(&replicas, removed, 5);
    assert_eq!(
        cluster.node(next).replace(agent, removed, 5).unwrap(),
        after
    );
    cluster.placed(agent, &after);
    cluster.converged(agent);
}

/// A replica down for good does not hold the group up once it is
/// replaced: the group compacts and takes the next change without it.
#[test]
fn a_replica_replaced_while_down_holds_nothing_up() {
    let mut cluster = Cluster::tuned(5, compacting);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.leader(agent);
    let mut followers = (1..=3).filter(|number| *number != leader);
    let (gone, other) = (followers.next().unwrap(), followers.next().unwrap());
    cluster.stop(gone);
    cluster.node(leader).replace(agent, gone, 4).unwrap();
    let start = log_start(cluster.node(leader), agent);
    cluster.increments(leader, agent, 1..=30);
    assert!(log_start(cluster.node(leader), agent) > start);
    let after = replaced(&replaced(&[1, 2, 3], gone, 4), other, 5);
    assert_eq!(
        cluster.node(leader).replace(agent, other, 5).unwrap(),
        after
    );
    cluster.placed(agent, &after);
}

/// A leader that removed itself and retired keeps its committed
/// placement when a later leader announces the same configuration before
/// it learns that it committed, naming the old leader among the nodes
/// before: the old leader does not start the group again.
#[test]
fn a_retired_leader_keeps_its_committed_placement() {
    let mut cluster = Cluster::new(4);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.leader(agent);
    cluster.node(leader).replace(agent, leader, 4).unwrap();
    retired(cluster.node(leader), agent);
    let next = cluster.leader(agent);
    // Settled once the next leader has confirmed the removal and announced
    // it: the same committed placement on both, twice in a row.
    let settled = || {
        let held = cluster.node(leader).placement(agent)?;
        (held.committed && Some(&held) == cluster.node(next).placement(agent).as_ref())
            .then_some(held)
    };
    let mut held = None;
    wait_until("the placements settle", || {
        let first = settled();
        std::thread::sleep(Duration::from_millis(200));
        held = first.filter(|first| settled().as_ref() == Some(first));
        held.is_some()
    });
    let held = held.unwrap();
    let record = cluster
        .node(leader)
        .store()
        .agents()
        .unwrap()
        .into_iter()
        .find(|record| record.agent == agent)
        .unwrap();
    // One of the replicas, stopped, speaks for it.
    let replica = *held
        .replicas
        .iter()
        .find(|number| **number != next)
        .unwrap();
    let speaker = cluster.impersonate(replica);
    speaker.send(
        leader,
        &PeerMessage::Directory {
            record,
            placement: vos_wire::peer::Placement {
                before: [held.before.clone(), vec![leader]].concat(),
                term: held.term + 5,
                committed: false,
                ..held.clone()
            },
        },
    );
    std::thread::sleep(Duration::from_millis(300));
    assert!(cluster.node(leader).applied(agent).is_none());
    let kept = cluster.node(leader).placement(agent).unwrap();
    assert!(kept.committed && kept.term < held.term + 5 && !kept.admits(leader));
}

/// The leader replaces itself: it finalizes the change, steps down and
/// retires, and the agent goes on under a new leader.
#[test]
fn the_leader_replaces_itself() {
    let cluster = Cluster::new(4);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.leader(agent);
    assert_eq!(done(cluster.increment(leader, agent, 1, 5)), 5);
    let replicas = replaced(&[1, 2, 3], leader, 4);
    assert_eq!(
        cluster.node(leader).replace(agent, leader, 4).unwrap(),
        replicas
    );
    cluster.placed(agent, &replicas);
    retired(cluster.node(leader), agent);
    let next = cluster.leader(agent);
    assert_ne!(next, leader);
    assert_eq!(done(cluster.increment(next, agent, 2, 1)), 6);
    cluster.converged(agent);
}

/// With elections as slow as a deployment's, a leader replacing itself
/// is answered without waiting for the next leader: it says where the
/// agent runs as it steps down.
#[test]
fn a_leader_replacing_itself_is_answered_before_the_next_election() {
    let cluster = Cluster::tuned(4, |_, config| {
        config.election_timeout_ms = (2500, 3000);
    });
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.leader(agent);
    let replicas = replaced(&[1, 2, 3], leader, 4);
    assert_eq!(
        cluster.node(leader).replace(agent, leader, 4).unwrap(),
        replicas
    );
    cluster.placed(agent, &replicas);
    retired(cluster.node(leader), agent);
}

/// A retirement a crash cut short: the node holds the placement that no
/// longer names it, and its replica's log and state. Started cut off from
/// every other node, it finishes the retirement on its own.
#[test]
fn a_retirement_cut_short_finishes_at_the_next_start() {
    let mut cluster = Cluster::new(4);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let (leader, removed) = cluster.leader_and_follower(agent);
    assert_eq!(done(cluster.increment(leader, agent, 1, 3)), 3);
    cluster.converged(agent);
    cluster.stop(removed);
    cluster.node(leader).replace(agent, removed, 4).unwrap();
    let placement = cluster.node(leader).placement(agent).unwrap();
    {
        let store =
            Fjall::open(cluster.dirs[usize::from(removed) - 1].path().join("store")).unwrap();
        assert!(
            store.raft(agent).unwrap().applied > 0,
            "the replica's state"
        );
        let mut batch = store.batch();
        batch.placement(agent, &placement);
        batch.commit(PersistMode::SyncAll).unwrap();
    }
    cluster.hub.isolate(removed);
    cluster.start(removed);
    retired(cluster.node(removed), agent);
    wait_until("the old epoch is dropped", || {
        cluster
            .node(removed)
            .store()
            .stale_epochs(agent)
            .unwrap()
            .is_empty()
    });
}

/// A leader cut off before its joint configuration reaches a majority
/// announces it to the node it would add, which starts the group; the
/// next leader's placement outranks it, and that node stops. A second
/// replacement, at the next leader, then succeeds.
#[test]
fn a_phantom_placement_gives_way_to_the_next_leader() {
    let cluster = Cluster::new(4);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.leader(agent);
    let followers: Vec<NodeNumber> = (1..=3).filter(|number| *number != leader).collect();
    for follower in &followers {
        cluster.hub.partition(leader, *follower);
    }
    std::thread::scope(|scope| {
        let cluster = &cluster;
        let gone = followers[1];
        let replacing = scope.spawn(move || cluster.node(leader).replace(agent, gone, 4));
        wait_until("the node it would add starts the group", || {
            cluster.node(4).applied(agent).is_some()
        });
        assert!(replacing.join().unwrap().is_err(), "never committed");
    });
    let next = loop {
        let next = cluster.leader(agent);
        if next != leader {
            break next;
        }
    };
    retired(cluster.node(4), agent);
    cluster.hub.heal();
    let replicas = replaced(&[1, 2, 3], followers[1], 4);
    assert_eq!(
        cluster.node(next).replace(agent, followers[1], 4).unwrap(),
        replicas
    );
    cluster.placed(agent, &replicas);
    cluster.converged(agent);
}

/// The leader cut off once its joint configuration committed, as it
/// appends the final one: the next leader finalizes the change, and says
/// so.
#[test]
fn the_next_leader_finalizes_a_joint_configuration() {
    let cluster = Cluster::new(4);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let (leader, removed) = cluster.leader_and_follower(agent);
    std::thread::scope(|scope| {
        let cluster = &cluster;
        scope.spawn(move || {
            let _ = cluster.node(leader).replace(agent, removed, 4);
        });
        // The core appends the final configuration once the joint one
        // commits.
        wait_until("the final configuration is appended", || {
            cluster
                .node(leader)
                .placement(agent)
                .is_some_and(|placement| placement.replicas.contains(&4) && !placement.joint)
        });
        cluster.hub.isolate(leader);
    });
    let replicas = replaced(&[1, 2, 3], removed, 4);
    wait_until("the final placement elsewhere", || {
        cluster
            .running()
            .filter(|(number, _)| *number != leader)
            .all(|(_, node)| {
                node.placement(agent).is_some_and(|placement| {
                    placement.replicas == replicas && placement.committed && !placement.joint
                })
            })
    });
    cluster.hub.heal();
    cluster.placed(agent, &replicas);
    retired(cluster.node(removed), agent);
}

/// A replica down while it is replaced comes back with its old log: it
/// does not disturb the group, and retires once it hears where the agent
/// runs.
#[test]
fn a_removed_replica_back_with_its_old_log_disturbs_nothing() {
    let mut cluster = Cluster::new(4);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let (leader, removed) = cluster.leader_and_follower(agent);
    assert_eq!(done(cluster.increment(leader, agent, 1, 3)), 3);
    cluster.converged(agent);
    cluster.stop(removed);
    let replicas = replaced(&[1, 2, 3], removed, 4);
    assert_eq!(
        cluster.node(leader).replace(agent, removed, 4).unwrap(),
        replicas
    );
    let term = |cluster: &Cluster| cluster.node(leader).store().raft(agent).unwrap().hard.term;
    let before = term(&cluster);
    cluster.start(removed);
    retired(cluster.node(removed), agent);
    assert_eq!(cluster.leader(agent), leader);
    assert_eq!(term(&cluster), before, "no election");
    cluster.placed(agent, &replicas);
}

/// A node that cannot run the agent's program is refused before the
/// group's configuration changes.
#[test]
fn a_replacement_by_a_node_that_cannot_run_the_program_is_refused() {
    // Node 4 runs another program as its agent program.
    let counter = actor("counter");
    let cluster = Cluster::tuned(4, move |number, config| {
        if number == 4 {
            config.agent = counter.clone();
        }
    });
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    let (leader, removed) = cluster.leader_and_follower(agent);
    assert!(matches!(
        cluster.node(leader).replace(agent, removed, 4),
        Err(vos_node::ReplaceError::Unplaced(Unplaced::CannotRun))
    ));
    let placement = cluster.node(leader).placement(agent).unwrap();
    assert_eq!(placement.replicas, vec![1, 2, 3]);
    assert!(!placement.joint);
}

/// A leader that still believes it leads, though its followers elected
/// another that replaced it, retires once it hears the committed final
/// placement: its Raft frames, both ways, and its pair heartbeat to its
/// followers are lost, while it still hears theirs.
#[test]
fn a_stale_leader_left_out_of_the_configuration_retires() {
    let cluster = Cluster::new(4);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let stale = cluster.leader(agent);
    let followers: Vec<NodeNumber> = (1..=3).filter(|number| *number != stale).collect();
    for &follower in &followers {
        cluster
            .hub
            .cut_class(stale, follower, vos_net::Class::Consensus);
        cluster
            .hub
            .cut_class(follower, stale, vos_net::Class::Consensus);
        cluster
            .hub
            .cut_class(stale, follower, vos_net::Class::Liveness);
    }
    let next = loop {
        let leading: Vec<NodeNumber> = followers
            .iter()
            .copied()
            .filter(|number| cluster.node(*number).leads(agent))
            .collect();
        if let [next] = leading[..] {
            break next;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(
        cluster.node(stale).leads(agent),
        "the stale one still leads"
    );
    let replicas = replaced(&[1, 2, 3], stale, 4);
    assert_eq!(
        cluster.node(next).replace(agent, stale, 4).unwrap(),
        replicas
    );
    cluster.hub.heal();
    retired(cluster.node(stale), agent);
}

/// A replica retired twice keeps the floor its first retirement left.
/// Added again and removed before it held any entry, its empty log alone
/// would lower the floor below what it once held, and it could then vote
/// for a candidate missing entries it had acknowledged.
#[test]
fn a_replica_retired_twice_keeps_its_first_floor() {
    let cluster = Cluster::new(4);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let (leader, gone) = cluster.leader_and_follower(agent);
    cluster.increments(leader, agent, 1..=5);
    wait_until("the replica holds every entry", || {
        cluster.node(gone).applied(agent) >= cluster.node(leader).applied(agent)
    });
    let held = cluster.node(gone).applied(agent).unwrap();
    let first = replaced(&[1, 2, 3], gone, 4);
    assert_eq!(cluster.node(leader).replace(agent, gone, 4).unwrap(), first);
    retired(cluster.node(gone), agent);
    let floor = cluster
        .node(gone)
        .store()
        .raft(agent)
        .unwrap()
        .vote_floor
        .expect("a floor");
    assert!(floor.0 >= held, "the floor {floor:?} is below {held}");

    // Added again with no entry reaching it: its directory still learns.
    for number in (1..=4).filter(|number| *number != gone) {
        cluster
            .hub
            .cut_class(gone, number, vos_net::Class::Consensus);
        cluster
            .hub
            .cut_class(number, gone, vos_net::Class::Consensus);
    }
    let leader = cluster.leader(agent);
    let again = replaced(&first, 4, gone);
    assert_eq!(cluster.node(leader).replace(agent, 4, gone).unwrap(), again);
    wait_until("the replica runs the group again", || {
        cluster.node(gone).applied(agent).is_some()
    });
    assert!(
        cluster
            .node(gone)
            .store()
            .raft(agent)
            .unwrap()
            .log
            .is_empty()
    );
    // The retirement's batch moves the state to a new, empty epoch: once
    // the epoch moves, its floor is written.
    let epoch = cluster.node(gone).store().snapshot().epoch(agent).unwrap();
    assert_eq!(cluster.node(leader).replace(agent, gone, 4).unwrap(), first);
    retired(cluster.node(gone), agent);
    wait_until("the retirement is written", || {
        cluster.node(gone).store().snapshot().epoch(agent).unwrap() != epoch
    });
    assert_eq!(
        cluster.node(gone).store().raft(agent).unwrap().vote_floor,
        Some(floor),
        "the second retirement lowered the floor"
    );
}
