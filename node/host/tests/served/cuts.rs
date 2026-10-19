//! The checker's exactly-once run with window cuts: windows of two seconds,
//! so a run crosses dozens of boundaries through its failures (leaders
//! stopped, nodes cut off, clocks jumping, snapshots installed), with a
//! writer at each agent rewriting rows of the reader's committed map, and
//! a reader starting workflows that read sixteen of them at their window's
//! cut ([`vos_wire::abi::Op::AttestAt`]), each served by its leader with a
//! stand-in for the space's representative.
//!
//! Beside the run's own checks: undo rows were held during it, by some
//! replica, and none is left once every replica has built; every replica
//! records the same cuts, and holds the same replicated rows, its
//! node-local ones (undo rows, roots at cuts, proofs) apart; the roots at
//! the two latest cuts are the same on every replica; every read ended, many
//! served and stated, none refused by its kernel, and no request or proof
//! is left on any replica.
//!
//! `CUTS_FULL` adds the workflows' tours, the checker loop's run;
//! `EXACTLY_ONCE_SEED` picks the seed.

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use vos_checker::calls::install_at_leader;
use vos_checker::programs::{actor, method, package};
use vos_checker::{ANSWERED, Mode, wait_until};
use vos_node::Reply;
use vos_node::roots;
use vos_node::store::Snapshot;
use vos_wire::abi::AttestError;
use vos_wire::abi::Failure;
use vos_wire::batch::Request;
use vos_wire::ids::{AgentId, InstanceId, Principal, Session, WorkflowId};
use vos_wire::keys;
use vos_wire::records::{Workflow, WorkflowState, unstored};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, WindowClock};

use crate::exactly_once::{Alongside, exactly_once};
use crate::harness::{Cluster, NODES};
use vos_checker::rounds::Rounds;

/// Windows of two seconds: no venue registers them, and none is asked to.
const CLOCK: WindowClock = WindowClock {
    origin_ms: 0,
    length_ms: 2_000,
};
/// The writers' keys in the reader's committed map.
const KEYS: u64 = 200;
/// The reader, installed in every agent of the run.
const READER: InstanceId = InstanceId(9);

/// The sixteen keys each read names: twelve the writers write, four they
/// never do.
fn read_keys() -> Vec<u64> {
    (0..16u64)
        .map(|index| {
            if index < 12 {
                index * 13 % KEYS
            } else {
                KEYS + index
            }
        })
        .collect()
}

/// A client's session of its own at `agent`, keyed `key`, the `name`th.
fn session(cluster: &Cluster, key: u8, name: u128) -> Session {
    Session {
        key: [key; 32],
        name: name.to_le_bytes(),
        t0: vos_node::wall_clock().saturating_add_signed(cluster.offset.load(Ordering::SeqCst)),
    }
}

/// The cuts, the writers, the readers and the sampler of undo rows.
struct Cuts {
    /// How often a sample found undo rows on some replica.
    undo_held: Mutex<u64>,
    /// The reads started, by agent.
    started: Mutex<Vec<(AgentId, WorkflowId)>>,
}

impl Cuts {
    /// Rewrite rows of `agent`'s reader's committed map until `done`, in a
    /// session of its own, started again whenever the agent refuses it.
    fn write(&self, cluster: &Cluster, agent: AgentId, done: &AtomicBool) {
        let set_entries = method(&actor("reader"), "set_entries");
        let mut name = 0u128;
        let mut session = None;
        let mut sequence = 0;
        while !done.load(Ordering::SeqCst) {
            if cluster.paused.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            }
            let current = *session.get_or_insert_with(|| {
                name += 1;
                sequence = 1;
                self::session(cluster, 9, name)
            });
            let writes: Vec<(u64, Option<u64>)> = (0..8u64)
                .map(|index| {
                    let key = (sequence * 31 + index * 7) % KEYS;
                    (key, (key % 5 != sequence % 5).then_some(sequence))
                })
                .collect();
            let request = Request {
                session: current,
                sequence,
                caller: Principal::Client([9; 32]),
                instance: READER,
                method: set_entries,
                arguments: writes.encode(),
            };
            let Some(node) = cluster
                .leader(agent)
                .and_then(|number| cluster.node(number))
            else {
                std::thread::sleep(Duration::from_millis(20));
                continue;
            };
            match smol::block_on(node.call(agent, request)) {
                Ok(Reply::Ran(Outcome::Done(_))) => sequence += 1,
                Ok(_) => session = None,
                Err(_) => {
                    std::thread::sleep(Duration::from_millis(20));
                }
            }
        }
    }

    /// Start reads of `agent`'s reader at their window's cut until `done`,
    /// a few a window, each in a session of its own's next request.
    fn read(&self, cluster: &Cluster, agent: AgentId, done: &AtomicBool) {
        let sum_at_cut = method(&actor("reader"), "sum_at_cut");
        let mut name = 0u128;
        let mut session = None;
        let mut sequence = 0;
        while !done.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(300));
            if cluster.paused.load(Ordering::SeqCst) {
                continue;
            }
            let current = *session.get_or_insert_with(|| {
                name += 1;
                sequence = 1;
                self::session(cluster, 8, name)
            });
            let request = Request {
                session: current,
                sequence,
                caller: Principal::Client([8; 32]),
                instance: READER,
                method: sum_at_cut,
                arguments: read_keys().encode(),
            };
            let Some(node) = cluster
                .leader(agent)
                .and_then(|number| cluster.node(number))
            else {
                continue;
            };
            match smol::block_on(node.call(agent, request)) {
                Ok(Reply::Ran(Outcome::Started(id))) => {
                    self.started.lock().unwrap().push((agent, id));
                    sequence += 1;
                }
                Ok(_) => session = None,
                Err(_) => {}
            }
        }
    }

    /// Count, until `done`, the samples in which some running replica of
    /// some agent holds undo rows.
    fn sample(&self, cluster: &Cluster, agents: &[(AgentId, [u8; 32])], done: &AtomicBool) {
        while !done.load(Ordering::SeqCst) {
            let held = (1..=NODES)
                .filter_map(|number| cluster.node(number))
                .any(|node| {
                    agents.iter().any(|(agent, _)| {
                        node.store()
                            .snapshot()
                            .scan(*agent, &keys::undo_prefix(), None)
                            .next()
                            .is_some()
                    })
                });
            if held {
                *self.undo_held.lock().unwrap() += 1;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
    }
}

impl Alongside for Cuts {
    fn clock(&self) -> Option<WindowClock> {
        Some(CLOCK)
    }

    fn run(&self, cluster: &Cluster, agents: &[(AgentId, [u8; 32])], done: &AtomicBool) {
        let reader = package("reader");
        for (agent, _) in agents {
            install_at_leader(|| cluster.leading(*agent), *agent, READER, &reader);
        }
        for number in 1..=NODES {
            cluster
                .slot(number)
                .trip
                .stand_in
                .store(true, Ordering::SeqCst);
        }
        std::thread::scope(|scope| {
            for (agent, _) in agents {
                scope.spawn(move || self.write(cluster, *agent, done));
                scope.spawn(move || self.read(cluster, *agent, done));
            }
            scope.spawn(move || self.sample(cluster, agents, done));
        });
    }

    fn check(&self, cluster: &Cluster, agents: &[(AgentId, [u8; 32])]) {
        let held = *self.undo_held.lock().unwrap();
        println!("samples holding undo rows: {held}");
        assert!(held > 0, "no replica held an undo row");
        let started = self.started.lock().unwrap().clone();
        let mut served = 0;
        for (agent, _) in agents {
            let reads: Vec<WorkflowId> = started
                .iter()
                .filter(|(at, _)| at == agent)
                .map(|(_, id)| *id)
                .collect();
            served += check_reads(cluster, *agent, &reads);
            check_agent(cluster, *agent);
        }
        assert!(served > 0, "no read served");
    }
}

/// The cuts `snapshot` holds of `agent`.
fn cuts(snapshot: &Snapshot, agent: AgentId) -> BTreeMap<u64, u64> {
    snapshot
        .scan(agent, &keys::cuts(), None)
        .map(|row| {
            let (key, value) = row.unwrap();
            let version = u64::decode(unstored(&value).unwrap()).unwrap().0;
            (keys::cut_entry(&key).unwrap(), version)
        })
        .collect()
}

/// `agent`'s replicated rows in `snapshot` ([`keys::is_replicated`]).
fn replicated(snapshot: &Snapshot, agent: AgentId) -> Vec<(Vec<u8>, Vec<u8>)> {
    [[0x00u8], [0x01], [0x03]]
        .iter()
        .flat_map(|prefix| snapshot.scan(agent, prefix, None).map(Result::unwrap))
        .filter(|(key, _)| keys::is_replicated(key))
        .collect()
}

/// Once every replica applies as far as the others and has built every
/// cut and its latest version: the same cuts, dozens of them, and the same
/// replicated rows; the same roots at the two latest cuts; no undo row, no
/// pending request and no request's proof left, every read answered.
fn check_agent(cluster: &Cluster, agent: AgentId) {
    let nodes: Vec<_> = (1..=NODES)
        .map(|number| cluster.node(number).unwrap())
        .collect();
    let mut snapshots = Vec::new();
    wait_until("every replica builds its every cut", ANSWERED, || {
        snapshots = nodes.iter().map(|node| node.store().snapshot()).collect();
        let applied: Vec<_> = snapshots
            .iter()
            .map(|snapshot| snapshot.applied(agent).unwrap())
            .collect();
        applied.windows(2).all(|pair| pair[0] == pair[1])
            && snapshots.iter().all(|snapshot| {
                [keys::dirty_prefix(), keys::undo_prefix()]
                    .iter()
                    .all(|prefix| snapshot.scan(agent, prefix, None).next().is_none())
            })
    });
    let recorded = cuts(&snapshots[0], agent);
    println!("agent {}: {} cuts", agent.0, recorded.len());
    assert!(
        recorded.len() >= 10,
        "agent {}: {} cuts",
        agent.0,
        recorded.len()
    );
    let rows = replicated(&snapshots[0], agent);
    for snapshot in &snapshots[1..] {
        assert_eq!(
            cuts(snapshot, agent),
            recorded,
            "agent {}: the cuts",
            agent.0
        );
        assert!(
            replicated(snapshot, agent) == rows,
            "agent {}: the replicated rows",
            agent.0
        );
    }
    for window in recorded.keys().rev().take(2) {
        let root = roots::cut_root(&snapshots[0], agent, *window).unwrap();
        let root = root.unwrap_or_else(|| panic!("agent {}: cut({window}) kept", agent.0));
        assert_eq!(root.1, recorded[window]);
        for snapshot in &snapshots[1..] {
            assert_eq!(
                roots::cut_root(snapshot, agent, *window).unwrap(),
                Some(root)
            );
        }
    }
    for snapshot in &snapshots {
        for prefix in [keys::request_prefix(), keys::cut_proofs()] {
            assert!(
                snapshot.scan(agent, &prefix, None).next().is_none(),
                "agent {}: a request or its proof left",
                agent.0
            );
        }
    }
}

/// Every read `agent`'s reader started ended on every replica, its record
/// read or, a clock's jump past its keeping, collected: those read served
/// and stated, not served in time, or, of a window such a jump left uncut,
/// unserved; none refused by its kernel. How many were read served.
fn check_reads(cluster: &Cluster, agent: AgentId, reads: &[WorkflowId]) -> usize {
    let nodes: Vec<_> = (1..=NODES)
        .map(|number| cluster.node(number).unwrap())
        .collect();
    let mut outcomes = BTreeMap::new();
    wait_until("every read ends on every replica", ANSWERED, || {
        outcomes.clear();
        nodes.iter().all(|node| {
            let snapshot = node.store().snapshot();
            reads.iter().all(|id| match ended(&snapshot, agent, *id) {
                Some(Some(outcome)) => {
                    outcomes.insert(*id, outcome);
                    true
                }
                Some(None) => true,
                None => false,
            })
        })
    });
    let failed = |error: AttestError| Outcome::Failed {
        code: Failure::Handler,
        detail: error.encode(),
    };
    let count =
        |of: &dyn Fn(&Outcome) -> bool| outcomes.values().filter(|outcome| of(outcome)).count();
    let served = count(&|outcome| matches!(outcome, Outcome::Done(_)));
    let late = count(&|outcome| *outcome == failed(AttestError::NotClosed));
    let unserved = count(&|outcome| *outcome == failed(AttestError::Unserved));
    println!(
        "agent {}: {} reads, {} collected, {served} served, {late} not served in time, \
         {unserved} unserved",
        agent.0,
        reads.len(),
        reads.len() - outcomes.len(),
    );
    assert_eq!(served + late + unserved, outcomes.len(), "{outcomes:?}");
    served
}

/// Workflow `id`'s outcome in `snapshot` once it ended, `Some(None)` once
/// it is collected, or `None` while it runs.
fn ended(snapshot: &Snapshot, agent: AgentId, id: WorkflowId) -> Option<Option<Outcome>> {
    let Some(bytes) = snapshot.get(agent, &keys::workflow(id)).unwrap() else {
        return Some(None);
    };
    let record = Workflow::decode(unstored(&bytes)?).ok()?.0;
    match record.state {
        WorkflowState::Ended(outcome) => Some(Some(outcome)),
        _ => None,
    }
}

/// The exactly-once run with window cuts, its replicas' states equal
/// though each holds its own undo rows. With `CUTS_FULL` set, the run
/// tours workflows as well, as the checker loop runs it.
#[test]
fn cuts_apply_once_and_replicas_agree_through_failures() {
    let cuts = Cuts {
        undo_held: Mutex::new(0),
        started: Mutex::new(Vec::new()),
    };
    let rounds = std::env::var_os("CUTS_FULL").map(|_| Rounds::load());
    exactly_once(Mode::OneAtATime, 0x5eed_0612, rounds, Some(&cuts));
}
