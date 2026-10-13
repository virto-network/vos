//! Logs compacting on nodes in one process, and followers behind a
//! compaction catching up by a snapshot: under load, over a slow link,
//! cut short, and once the programs it names are there.

use std::sync::Arc;
use std::time::{Duration, Instant};

use vos_checker::calls::done;
use vos_node::{Hooks, Node};

use crate::common::{Cluster, WithholdBlobs, compacting, log_start, wait_until};

#[test]
fn every_replica_compacts_its_log_as_it_applies() {
    let cluster = Cluster::tuned(3, compacting);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.leader(agent);
    cluster.increments(leader, agent, 1..=40);
    cluster.converged(agent);
    wait_until("every replica compacts", || {
        cluster.running().all(|(_, node)| {
            let rows = node.store().raft(agent).unwrap();
            rows.log_start.0 > 20 && rows.log.len() < 20
        })
    });
}

/// A log compacts on its bytes long before its length, and keeps a tail
/// bounded in bytes: here no count would ever compact it.
#[test]
fn a_log_compacts_on_its_bytes_and_keeps_a_tail_within_them() {
    let cluster = Cluster::tuned(3, |_, config| {
        config.compact_every = u64::MAX;
        config.compact_tail = u64::MAX;
        config.snapshot_chunk = 64;
        config.compact_bytes = 1024;
        config.compact_tail_bytes = 256;
    });
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.leader(agent);
    cluster.increments(leader, agent, 1..=40);
    cluster.converged(agent);
    // Each entry counts at least 64 bytes, so the log holds at most 16
    // past its start before a compaction is due.
    wait_until("every replica compacts", || {
        cluster.running().all(|(_, node)| {
            let rows = node.store().raft(agent).unwrap();
            rows.log_start.0 > 20 && rows.log.len() <= 16
        })
    });
}

/// A follower down while the log is compacted past it catches up by a
/// snapshot, under load: the same state, last result and pins, the
/// program it missed fetched before the switch, and its queries answer
/// the same.
#[test]
fn a_follower_behind_the_log_catches_up_by_a_snapshot() {
    let mut cluster = Cluster::tuned(3, compacting);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    let (leader, follower) = cluster.leader_and_follower(agent);
    wait_until("the follower runs the group", || {
        cluster.node(follower).applied(agent).is_some()
    });
    cluster.stop(follower);
    cluster.install(agent);
    cluster.increments(leader, agent, 1..=30);
    cluster.compacted_past(leader, agent, 20);
    cluster.start(follower);
    // Calls go on while it catches up.
    let total = std::thread::scope(|scope| {
        let cluster = &cluster;
        scope
            .spawn(move || cluster.increments(leader, agent, 31..=60))
            .join()
            .unwrap()
    });
    cluster.converged(agent);
    let caught_up = cluster.node(follower);
    assert!(log_start(caught_up, agent) > 20, "installed a snapshot");
    assert_eq!(caught_up.pinned(), cluster.node(leader).pinned());
    assert!(!caught_up.pinned().is_empty(), "the program it missed");
    let last = |node: &Node| node.store().snapshot().last_result(agent).unwrap();
    assert_eq!(last(caught_up), last(cluster.node(leader)));
    assert_eq!(cluster.value(follower, agent), total);
    assert!(
        caught_up.store().stale_epochs(agent).unwrap().is_empty(),
        "the old epoch is dropped"
    );
}

/// Slows every snapshot chunk, as a slow link would.
struct SlowChunks(Duration);

impl Hooks for SlowChunks {
    fn delay_chunk(&self) -> Duration {
        self.0
    }
}

/// A snapshot stream that outlasts the leader's own deadline for it goes
/// on, and no other starts while it runs: the follower switches to it
/// once, and catches up.
#[test]
fn a_snapshot_stream_outlasting_the_leaders_deadline_goes_on() {
    let slow = Arc::new(SlowChunks(Duration::from_millis(40)));
    let mut cluster = Cluster::tuned(3, move |number, config| {
        compacting(number, config);
        config.snapshot_timeout_ms = 300;
        config.hooks = slow.clone();
    });
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    let (leader, follower) = cluster.leader_and_follower(agent);
    wait_until("the follower runs the group", || {
        cluster.node(follower).applied(agent).is_some()
    });
    cluster.stop(follower);
    cluster.install(agent);
    let total = cluster.increments(leader, agent, 1..=30);
    cluster.compacted_past(leader, agent, 20);
    let started = Instant::now();
    cluster.start(follower);
    cluster.converged(agent);
    let caught_up = cluster.node(follower);
    assert!(log_start(caught_up, agent) > 20, "installed a snapshot");
    assert!(
        started.elapsed() > Duration::from_millis(300),
        "the stream outlasted the deadline: {:?}",
        started.elapsed()
    );
    assert_eq!(caught_up.snapshots_installed(), 1, "switched once");
    assert_eq!(
        cluster.node(leader).snapshots_streamed(),
        1,
        "no other stream started"
    );
    assert_eq!(cluster.value(follower, agent), total);
}

/// A replica that caught up by a snapshot holds the sessions with it: once
/// it leads, a call it never ran is answered from the window.
#[test]
fn a_replica_caught_up_by_a_snapshot_answers_from_its_window_when_it_leads() {
    let mut cluster = Cluster::tuned(3, compacting);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let (leader, follower) = cluster.leader_and_follower(agent);
    cluster.stop(follower);
    let total = cluster.increments(leader, agent, 1..=30);
    cluster.compacted_past(leader, agent, 20);
    cluster.start(follower);
    cluster.converged(agent);
    assert!(log_start(cluster.node(follower), agent) > 20);
    // Leadership moves until it reaches the replica that caught up.
    let until = Instant::now() + Duration::from_secs(20);
    while cluster.leader(agent) != follower {
        assert!(Instant::now() < until, "it never led");
        let current = cluster.leader(agent);
        cluster.stop(current);
        wait_until("another leader", || {
            cluster
                .running()
                .any(|(number, node)| number != current && node.leads(agent))
        });
        cluster.start(current);
        cluster.converged(agent);
    }
    assert_eq!(done(cluster.increment(follower, agent, 30, 30)), total);
    assert_eq!(cluster.value(follower, agent), total);
}

/// A snapshot cut short, by its follower stopping or its leader stopping,
/// still ends in one: the follower holds the same state, and no staged
/// rows are left behind.
#[test]
fn a_snapshot_cut_short_is_sent_again() {
    let mut cluster = Cluster::tuned(3, compacting);
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let (leader, follower) = cluster.leader_and_follower(agent);
    cluster.stop(follower);
    // Enough rows for many chunks.
    let total = cluster.increments(leader, agent, 1..=60);
    cluster.compacted_past(leader, agent, 40);
    // Its follower stops while it stages.
    cluster.start(follower);
    std::thread::sleep(Duration::from_millis(15));
    cluster.stop(follower);
    cluster.start(follower);
    // Its leader stops while it streams.
    std::thread::sleep(Duration::from_millis(15));
    cluster.stop(leader);
    cluster.start(leader);
    cluster.converged(agent);
    assert_eq!(cluster.value(follower, agent), total);
    wait_until("no staged rows are left", || {
        cluster
            .running()
            .all(|(_, node)| node.store().stale_epochs(agent).unwrap().is_empty())
    });
}

/// A snapshot switches only once the programs it names are here: while
/// every node withholds them, the follower stays behind.
#[test]
fn a_snapshot_waits_for_the_programs_it_names() {
    let withheld = Arc::new(WithholdBlobs::default());
    let hooks = Arc::clone(&withheld);
    let mut cluster = Cluster::tuned(3, move |number, config| {
        compacting(number, config);
        config.hooks = hooks.clone();
    });
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    let (leader, follower) = cluster.leader_and_follower(agent);
    wait_until("the follower runs the group", || {
        cluster.node(follower).applied(agent).is_some()
    });
    cluster.stop(follower);
    cluster.install(agent);
    cluster.increments(leader, agent, 1..=30);
    cluster.compacted_past(leader, agent, 20);
    withheld.withhold(true);
    cluster.start(follower);
    wait_until("the follower stages the snapshot", || {
        !cluster
            .node(follower)
            .store()
            .stale_epochs(agent)
            .unwrap()
            .is_empty()
    });
    // Time for every chunk to arrive.
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        log_start(cluster.node(follower), agent),
        0,
        "switched without the program"
    );
    assert!(cluster.node(follower).pinned().is_empty());
    withheld.withhold(false);
    cluster.converged(agent);
    assert_eq!(
        cluster.node(follower).pinned(),
        cluster.node(leader).pinned()
    );
}
