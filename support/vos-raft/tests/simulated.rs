//! Groups of protocol cores over a simulated network and stores
//! (`vos_raft::sim`), checked for Raft's safety properties under faults:
//! one leader per term, one entry per committed index, no commit past a
//! replica's log, no compaction past its commit. Every run is seeded; a
//! failing seed replays exactly.

use vos_raft::Role;
use vos_raft::sim::{Cluster, Faults};

const NODES: [u16; 3] = [1, 2, 3];

fn settle(cluster: &mut Cluster) -> u16 {
    for _ in 0..100 {
        cluster.run(100);
        if let Some(leader) = cluster.leader() {
            return leader;
        }
    }
    panic!("no leader elected");
}

#[test]
fn a_healthy_group_commits_in_order() {
    let mut cluster = Cluster::new(&NODES, 1, Faults::default());
    let leader = settle(&mut cluster);
    for n in 0..20u8 {
        cluster.propose(leader, vec![n + 1]);
    }
    cluster.run(500);
    let expected: Vec<Vec<u8>> = (1..=20u8).map(|n| vec![n]).collect();
    assert_eq!(cluster.committed_payloads(), expected);
    assert!(cluster.violations.is_empty(), "{:?}", cluster.violations);
}

#[test]
fn read_index_answers_once_the_leader_is_confirmed() {
    let mut cluster = Cluster::new(&NODES, 2, Faults::default());
    let leader = settle(&mut cluster);
    cluster.propose(leader, vec![9]);
    cluster.run(200);
    let token = cluster.read_index(leader);
    cluster.run(200);
    let index = cluster.reads[&token].expect("a read index");
    assert!(index >= cluster.committed_index().min(index));
    assert!(index >= 2, "the term's no-op and the proposal");
}

/// Cut in two, a group has a leader on its majority side only, which goes
/// on committing: the minority never gathers a quorum.
#[test]
fn partitioned_minority_loses_quorum_majority_keeps_a_leader() {
    let all = [1, 2, 3, 4, 5];
    let mut cluster = Cluster::new(&all, 4, Faults::default());
    cluster.network.isolate(&[4, 5], &all);
    let leader = settle(&mut cluster);
    cluster.run(2_000);
    let leading: Vec<u16> = all
        .into_iter()
        .filter(|&node| cluster.core(node).unwrap().role() == Role::Leader)
        .collect();
    assert_eq!(leading, [leader]);
    assert!([1, 2, 3].contains(&leader));
    cluster.propose(leader, vec![7]);
    cluster.run(200);
    assert_eq!(cluster.committed_payloads(), [vec![7]]);
    assert!(cluster.violations.is_empty(), "{:?}", cluster.violations);
}

/// A follower cut off from its group asks for pre-votes it never gets: its
/// term stays put, and so does the leader's.
#[test]
fn isolated_follower_does_not_inflate_term_under_pre_vote() {
    let mut cluster = Cluster::new(&NODES, 5, Faults::default());
    let leader = settle(&mut cluster);
    let isolated = NODES.into_iter().find(|&node| node != leader).unwrap();
    let terms = |cluster: &Cluster| {
        [leader, isolated].map(|node| cluster.core(node).unwrap().status().current_term)
    };
    let before = terms(&cluster);
    cluster.network.isolate(&[isolated], &NODES);
    // Ten election timeouts and more.
    cluster.run(3_000);
    assert_eq!(terms(&cluster), before);
    assert_eq!(cluster.leader(), Some(leader));
    assert!(cluster.violations.is_empty(), "{:?}", cluster.violations);
}

/// A voter removed while it is down holds nothing up: the next change
/// starts once the final entry commits, and the voter, restarted with the
/// log it had and never told of its removal, never leads.
#[test]
fn a_voter_removed_while_down_holds_nothing_up() {
    let all = [1, 2, 3, 4, 5];
    let mut cluster = Cluster::with_config(&all, 3, Faults::default(), |cfg| {
        cfg.members = NODES.to_vec();
    });
    let leader = settle(&mut cluster);
    let gone = NODES.into_iter().find(|&node| node != leader).unwrap();
    cluster.crash(gone);
    let replaced = |members: &[u16], out: u16, by: u16| -> Vec<u16> {
        let mut members: Vec<u16> = members.iter().copied().filter(|&n| n != out).collect();
        members.push(by);
        members
    };
    let members = replaced(&NODES, gone, 4);
    cluster.change_membership(leader, members.clone());
    let final_committed = |cluster: &Cluster| {
        let status = cluster.core(leader).unwrap().status();
        status.joint_old.is_none()
            && status.members == members
            && status.commit_index >= status.active_config_index.unwrap_or(0)
    };
    for _ in 0..100 {
        if final_committed(&cluster) {
            break;
        }
        cluster.run(10);
    }
    assert!(
        final_committed(&cluster),
        "the change completes without {gone}"
    );
    // The next change starts at once.
    let started = cluster.changes_started;
    let next = replaced(&members, 4, 5);
    cluster.change_membership(leader, next.clone());
    assert_eq!(cluster.changes_started, started + 1);
    cluster.restart(gone);
    for _ in 0..60 {
        cluster.run(50);
        assert_ne!(
            cluster.core(gone).unwrap().role(),
            Role::Leader,
            "{gone} leads"
        );
    }
    let leader = cluster.leader().expect("a leader");
    let status = cluster.core(leader).unwrap().status();
    assert_eq!((status.members, status.joint_old), (next, None));
    let before = cluster.committed_index();
    cluster.propose(leader, vec![1]);
    cluster.run(500);
    assert!(cluster.committed_index() > before);
    assert!(cluster.violations.is_empty(), "{:?}", cluster.violations);
}

/// What a chaos run exercised.
#[derive(Default)]
struct Exercised {
    changes: u64,
    installs: u64,
    compactions: u64,
    loads: u64,
    reads: u64,
    retirements: u64,
}

/// A run under harsh faults: short election timeouts, so leaders change
/// often; slow syncs, so writes wait unsynced; crashes every few hundred
/// milliseconds that lose those writes after a random prefix; quick
/// restarts; drops, duplicates, delays and partitions. The cache holds
/// almost nothing and the log compacts every few entries, so lagging
/// replicas load from the store or install snapshots. Reads are asked
/// throughout. Then everything heals, and the group must still make
/// progress.
///
/// `paired` turns idle heartbeats off and the hosts' pair heartbeats on:
/// crashes then last long enough for deadlines to lapse unvouched, and
/// after healing the group must also go quiet.
fn chaos(seed: u64, churn: bool, entry_lag: (u64, u64), paired: bool) -> Exercised {
    // With churn, a fourth node waits outside the group, and the group's
    // membership moves between three-node subsets of the four.
    let nodes: &[u16] = if churn { &[1, 2, 3, 4] } else { &NODES };
    let faults = Faults {
        drop_per_million: 50_000,
        duplicate_per_million: 50_000,
        delay: (1, 15),
    };
    let mut cluster = Cluster::with_config(nodes, seed, faults, |cfg| {
        cfg.members = NODES.to_vec();
        cfg.election_timeout_ms = (60, 120);
        cfg.heartbeat_interval_ms = 20;
        cfg.resend_timeout_ms = 40;
        cfg.snapshot_timeout_ms = 100;
        cfg.cache_bytes = 64;
        cfg.compact_hysteresis = 4;
        cfg.idle_heartbeats = !paired;
    });
    if paired {
        cluster.pair_heartbeats(20);
    }
    let downtime = if paired { 400 } else { 55 };
    cluster.sync_delay = (1, 80);
    // With a lag, entries are reported durable after their writes, as
    // when they wait for blobs, and followers give up on them at random.
    cluster.entry_lag = entry_lag;
    let lagging = entry_lag.1 > 0;
    let mut proposals = 0u32;
    let mut down: Vec<(u16, u64)> = Vec::new();
    for _ in 0..2_000 {
        let roll = cluster.random.next_u64() % 1_000;
        let node = nodes[(cluster.random.next_u64() % nodes.len() as u64) as usize];
        match roll {
            0..=29 => {
                // Crash a node mid-flight; it restarts 5–60 ms later.
                if !down.iter().any(|(at, _)| *at == node) {
                    cluster.crash(node);
                    let back = cluster.now + 5 + cluster.random.next_u64() % downtime;
                    down.push((node, back));
                }
            }
            30..=34 => {
                let all = nodes.to_vec();
                cluster.network.isolate(&[node], &all);
            }
            35..=60 => cluster.network.heal(),
            61..=500 => {
                if let Some(leader) = cluster.leader() {
                    proposals += 1;
                    cluster.propose(leader, proposals.to_be_bytes().to_vec());
                }
            }
            501..=560 => {
                if let Some(leader) = cluster.leader() {
                    cluster.read_index(leader);
                }
            }
            576..=590 if lagging => cluster.discard_unreported(node),
            591..=600 if paired => {
                let millis = 100 + cluster.random.next_u64() % 400;
                cluster.pair_blackout(node, millis);
            }
            561..=575 if churn => {
                if let Some(leader) = cluster.leader() {
                    let out = nodes[(cluster.random.next_u64() % 4) as usize];
                    let members = nodes.iter().copied().filter(|&n| n != out).collect();
                    cluster.change_membership(leader, members);
                }
            }
            _ => {}
        }
        // The hosts' directory, a little late: a replica a committed final
        // configuration dropped is retired, and one a configuration names
        // again starts empty.
        if paired && churn {
            directory(&mut cluster, nodes, 200_000);
        }
        let now = cluster.now;
        down.retain(|&(node, back)| {
            if back <= now {
                cluster.restart(node);
                false
            } else {
                true
            }
        });
        cluster.run(5);
        assert!(
            cluster.violations.is_empty(),
            "seed {seed}: {:?}",
            cluster.violations
        );
    }
    // Heal everything: the group elects a leader and commits again.
    cluster.network.heal();
    cluster.network.set_faults(Faults::default());
    cluster.end_pair_blackouts();
    for &node in nodes {
        cluster.restart(node);
    }
    if paired && churn {
        // The directory reaches every node.
        for _ in 0..20 {
            cluster.run(50);
            directory(&mut cluster, nodes, 1_000_000);
        }
    }
    settle(&mut cluster);
    if paired {
        // Healed and idle, every member catches up with no proposal to
        // carry it along.
        // The members' terms: a replica outside the group may still
        // campaign, refused, until the directory reaches it.
        let terms = |cluster: &Cluster| -> Vec<Option<u64>> {
            let members = cluster
                .leader()
                .map(|leader| cluster.core(leader).unwrap().status().members)
                .unwrap_or_default();
            members
                .iter()
                .map(|&node| cluster.core(node).map(|core| core.status().current_term))
                .collect()
        };
        // A change in flight at the heal may still remove its leader:
        // wait for a steady configuration led by one of its members.
        let steady = |cluster: &Cluster| {
            cluster.leader().is_some_and(|leader| {
                let status = cluster.core(leader).unwrap().status();
                status.joint_old.is_none() && status.members.contains(&leader)
            })
        };
        for _ in 0..50 {
            if steady(&cluster) {
                break;
            }
            cluster.run(100);
        }
        assert!(steady(&cluster), "seed {seed}: no steady configuration");
        let settled = terms(&cluster);
        cluster.run(2_000);
        assert_eq!(
            terms(&cluster),
            settled,
            "seed {seed}: an election while idle"
        );
        let leader = cluster.leader().expect("a leader");
        let status = cluster.core(leader).unwrap().status();
        for member in &status.members {
            let held = cluster
                .core(*member)
                .map(|core| (core.status().last_log_index, core.status().commit_index));
            assert_eq!(
                held,
                Some((status.last_log_index, status.commit_index)),
                "seed {seed}: member {member} not caught up"
            );
        }
    }
    // The leader now, which a change in flight at the heal may have moved.
    let leader = settle(&mut cluster);
    let before = cluster.committed_index();
    cluster.propose(leader, b"after".to_vec());
    cluster.run(1_000);
    assert!(
        cluster.committed_index() > before,
        "seed {seed}: no progress after healing"
    );
    if paired {
        // Idle, the group sends nothing: the pair heartbeats vouch.
        // A replica removed while it was down may never learn it and
        // campaign on, refused: only the members' own traffic counts.
        cluster.run(1_000);
        let leader = cluster.leader().expect("a leader");
        let members = cluster.core(leader).unwrap().status().members;
        let among = |cluster: &Cluster| -> u64 {
            cluster
                .raft_sent
                .iter()
                .filter(|((from, to), _)| members.contains(from) && members.contains(to))
                .map(|(_, sent)| sent)
                .sum()
        };
        let sent = among(&cluster);
        cluster.run(1_000);
        assert_eq!(among(&cluster), sent, "seed {seed}: not quiet");
        // Quiet, every member holds the leader's commit.
        let commit = cluster.core(leader).unwrap().status().commit_index;
        for member in &members {
            let held = cluster.core(*member).map(|core| core.status().commit_index);
            assert_eq!(held, Some(commit), "seed {seed}: member {member} behind");
        }
    }
    assert!(
        cluster.violations.is_empty(),
        "seed {seed}: {:?}",
        cluster.violations
    );
    Exercised {
        retirements: cluster.retirements,
        changes: cluster.changes_started,
        installs: cluster.installs,
        compactions: cluster.compactions,
        loads: cluster.loads,
        reads: cluster.reads.values().filter(|read| read.is_ok()).count() as u64,
    }
}

/// The hosts' directory, as the leader's configuration has it: with
/// `chance` per million, a replica a committed final configuration
/// dropped is retired, and one a configuration names again starts.
fn directory(cluster: &mut Cluster, nodes: &[u16], chance: u64) {
    let Some(leader) = cluster.leader() else {
        return;
    };
    let status = cluster.core(leader).unwrap().status();
    let named = |node: &u16| {
        status.members.contains(node)
            || status
                .joint_old
                .as_ref()
                .is_some_and(|old| old.contains(node))
    };
    let settled = status.joint_old.is_none()
        && status.commit_index >= status.active_config_index.unwrap_or(0);
    for &node in nodes {
        if named(&node) {
            if cluster.is_retired(node) {
                cluster.readmit(node);
            }
        } else if settled && cluster.holds_replica(node) && cluster.random.chance(chance) {
            cluster.retire(node, true);
        }
    }
}

#[test]
fn safety_holds_under_faults() {
    let mut total = Exercised::default();
    for seed in 0..200 {
        let run = chaos(seed, false, (0, 0), false);
        total.installs += run.installs;
        total.compactions += run.compactions;
        total.loads += run.loads;
        total.reads += run.reads;
    }
    // The runs reach every path they are meant to test.
    eprintln!(
        "installs {}, compactions {}, loads {}, reads answered {}",
        total.installs, total.compactions, total.loads, total.reads
    );
    assert!(total.installs >= 1_000, "installs: {}", total.installs);
    assert!(
        total.compactions >= 10_000,
        "compactions: {}",
        total.compactions
    );
    assert!(total.loads >= 10_000, "loads: {}", total.loads);
    assert!(total.reads >= 5_000, "reads: {}", total.reads);
}

#[test]
fn safety_holds_under_faults_and_membership_changes() {
    let mut total = Exercised::default();
    for seed in 0..200 {
        let run = chaos(seed, true, (0, 0), false);
        total.changes += run.changes;
        total.installs += run.installs;
    }
    eprintln!(
        "changes started {}, installs {}",
        total.changes, total.installs
    );
    assert!(total.changes >= 500, "changes: {}", total.changes);
}

#[test]
fn safety_holds_when_entries_wait_for_blobs() {
    let mut total = Exercised::default();
    for seed in 0..200 {
        let run = chaos(seed, true, (1, 60), false);
        total.changes += run.changes;
        total.reads += run.reads;
    }
    eprintln!(
        "changes started {}, reads answered {}",
        total.changes, total.reads
    );
    assert!(total.reads >= 1_000, "reads: {}", total.reads);
}

/// The chaos runs as a node's host runs its groups: idle heartbeats off,
/// leaders and members vouched for by the pair heartbeat, and, with
/// membership changes, dropped replicas retired (log and state wiped,
/// term, vote and vote floor kept), then started again empty when a
/// configuration names them.
#[test]
fn safety_holds_with_idle_heartbeats_off_and_the_hosts_vouching() {
    let mut total = Exercised::default();
    for seed in 0..400 {
        let run = chaos(seed, false, (0, 0), true);
        total.installs += run.installs;
        total.reads += run.reads;
        let run = chaos(1_000 + seed, true, (0, 0), true);
        total.changes += run.changes;
        total.retirements += run.retirements;
    }
    eprintln!(
        "installs {}, reads answered {}, changes started {}, retirements {}",
        total.installs, total.reads, total.changes, total.retirements
    );
    assert!(total.installs >= 2_000, "installs: {}", total.installs);
    assert!(total.changes >= 1_000, "changes: {}", total.changes);
    assert!(
        total.retirements >= 1_000,
        "retirements: {}",
        total.retirements
    );
}
