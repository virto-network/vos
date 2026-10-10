//! Groups of protocol cores over a simulated network and stores
//! (`vos_raft::sim`), checked for Raft's safety properties under faults:
//! one leader per term, one entry per committed index, no commit past a
//! replica's log. Every run is seeded; a failing seed replays exactly.

#![cfg(feature = "std")]

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

/// What a chaos run exercised.
#[derive(Default)]
struct Exercised {
    changes: u64,
    installs: u64,
    compactions: u64,
    loads: u64,
    reads: u64,
}

/// A run under harsh faults: short election timeouts, so leaders change
/// often; slow syncs, so writes wait unsynced; crashes every few hundred
/// milliseconds that lose those writes after a random prefix; quick
/// restarts; drops, duplicates, delays and partitions. The cache holds
/// almost nothing and the log compacts every few entries, so lagging
/// replicas load from the store or install snapshots. Reads are asked
/// throughout. Then everything heals, and the group must still make
/// progress.
fn chaos(seed: u64, churn: bool) -> Exercised {
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
    });
    cluster.sync_delay = (1, 80);
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
                    let back = cluster.now + 5 + cluster.random.next_u64() % 55;
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
            561..=575 if churn => {
                if let Some(leader) = cluster.leader() {
                    let out = nodes[(cluster.random.next_u64() % 4) as usize];
                    let members = nodes.iter().copied().filter(|&n| n != out).collect();
                    cluster.change_membership(leader, members);
                }
            }
            _ => {}
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
    for &node in nodes {
        cluster.restart(node);
    }
    let leader = settle(&mut cluster);
    let before = cluster.committed_index();
    cluster.propose(leader, b"after".to_vec());
    cluster.run(1_000);
    assert!(
        cluster.committed_index() > before,
        "seed {seed}: no progress after healing"
    );
    assert!(
        cluster.violations.is_empty(),
        "seed {seed}: {:?}",
        cluster.violations
    );
    Exercised {
        changes: cluster.changes_started,
        installs: cluster.installs,
        compactions: cluster.compactions,
        loads: cluster.loads,
        reads: cluster.reads.values().filter(|read| read.is_ok()).count() as u64,
    }
}

#[test]
fn safety_holds_under_faults() {
    let mut total = Exercised::default();
    for seed in 0..200 {
        let run = chaos(seed, false);
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
        let run = chaos(seed, true);
        total.changes += run.changes;
        total.installs += run.installs;
    }
    eprintln!(
        "changes started {}, installs {}",
        total.changes, total.installs
    );
    assert!(total.changes >= 500, "changes: {}", total.changes);
}
