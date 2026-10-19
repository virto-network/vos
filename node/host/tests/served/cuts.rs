//! The checker's exactly-once run with window cuts: windows of two seconds,
//! so a run crosses dozens of boundaries through its failures (leaders
//! stopped, nodes cut off, clocks jumping, snapshots installed), with a
//! writer at each agent rewriting rows of the counter's committed map, and
//! every leader's batches recording a pending request of their window that
//! reads sixteen of them ([`vos_node::Hooks::request_at_cut`]).
//!
//! Beside the run's own checks: undo rows were held during it, by some
//! replica, and none is left once every replica has built; every replica
//! records the same cuts, and holds the same replicated rows, its
//! node-local ones (undo rows, roots at cuts, proofs) apart; the roots at
//! the two latest cuts are the same on every replica, and each pending
//! request of those windows has the same proof on every replica, verifying
//! against that root.
//!
//! `CUTS_FULL` adds the workflows' tours, the checker loop's run;
//! `EXACTLY_ONCE_SEED` picks the seed.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vos_checker::programs::{actor, method, table_tag};
use vos_checker::{ANSWERED, Mode, wait_until};
use vos_node::Reply;
use vos_node::roots;
use vos_node::store::Snapshot;
use vos_tree::{Blake2b, Hash};
use vos_wire::batch::Request;
use vos_wire::ids::{AgentId, MapId, Principal, RequestId, Session, WorkflowId};
use vos_wire::keys::{self, Transform};
use vos_wire::records::{PendingRead, unstored};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, WindowClock};

use crate::exactly_once::{Alongside, exactly_once};
use crate::harness::{Asks, Cluster, NODES};
use vos_checker::COUNTER;
use vos_checker::rounds::Rounds;

/// Windows of two seconds: no venue registers them, and none is asked to.
const CLOCK: WindowClock = WindowClock {
    origin_ms: 0,
    length_ms: 2_000,
};
/// The writers' keys in the counter's committed map.
const KEYS: u64 = 200;

/// The counter's committed map.
fn entries() -> MapId {
    MapId {
        instance: COUNTER,
        tag: table_tag("entries"),
        transform: Transform::Hashed,
    }
}

/// The sixteen rows each request reads: twelve the writers write, four
/// they never do.
fn read_rows() -> Vec<Vec<u8>> {
    let mut rows: Vec<Vec<u8>> = (0..16u64)
        .map(|index| {
            let key = if index < 12 {
                index * 13 % KEYS
            } else {
                KEYS + index
            };
            keys::committed(&entries(), &Transform::Hashed.apply(&key.encode()))
        })
        .collect();
    rows.sort();
    rows
}

/// The cuts, the writers and the sampler of undo rows.
struct Cuts {
    /// How often a sample found undo rows on some replica.
    undo_held: Mutex<u64>,
}

impl Cuts {
    /// Rewrite rows of `agent`'s committed map until `done`, in a session
    /// of its own, started again whenever the agent refuses it.
    fn write(&self, cluster: &Cluster, agent: AgentId, done: &AtomicBool) {
        let set_entries = method(&actor("counter"), "set_entries");
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
                Session {
                    key: [9; 32],
                    name: name.to_le_bytes(),
                    t0: vos_node::wall_clock()
                        .saturating_add_signed(cluster.offset.load(Ordering::SeqCst)),
                }
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
                instance: COUNTER,
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
        // One request a window, named by it: every batch of the window
        // records the same row again, which changes nothing.
        let asks: Arc<Asks> = Arc::new(|_: AgentId, time: u64| {
            let window = CLOCK.window(time)?;
            Some((
                RequestId {
                    workflow: WorkflowId(window),
                    awaits: 0,
                },
                PendingRead {
                    instance: COUNTER,
                    rows: read_rows(),
                },
            ))
        });
        for number in 1..=NODES {
            *cluster.slot(number).trip.asks.lock().unwrap() = Some(asks.clone());
        }
        std::thread::scope(|scope| {
            for (agent, _) in agents {
                scope.spawn(move || self.write(cluster, *agent, done));
            }
            scope.spawn(move || self.sample(cluster, agents, done));
        });
    }

    fn check(&self, cluster: &Cluster, agents: &[(AgentId, [u8; 32])]) {
        let held = *self.undo_held.lock().unwrap();
        println!("samples holding undo rows: {held}");
        assert!(held > 0, "no replica held an undo row");
        for (agent, _) in agents {
            check_agent(cluster, *agent);
        }
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
/// replicated rows; the same roots at the two latest cuts; each pending
/// request of a cut window the same proof everywhere, at its window's cut,
/// of the rows it reads, verifying against its root, the root kept at that
/// cut while it is kept; no undo row left. Leaders cut idle agents' windows
/// meanwhile, so the latest cuts may hold no request.
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
    let latest: Vec<u64> = recorded.keys().rev().take(2).copied().collect();
    let mut roots: BTreeMap<u64, (Hash, u64)> = BTreeMap::new();
    for window in &latest {
        let root = roots::cut_root(&snapshots[0], agent, *window).unwrap();
        let root = root.unwrap_or_else(|| panic!("agent {}: cut({window}) kept", agent.0));
        assert_eq!(root.1, recorded[window]);
        for snapshot in &snapshots[1..] {
            assert_eq!(
                roots::cut_root(snapshot, agent, *window).unwrap(),
                Some(root)
            );
        }
        roots.insert(*window, root);
    }
    let mut proven = 0;
    for row in snapshots[0].scan(agent, &keys::request_prefix(), None) {
        let (key, value) = row.unwrap();
        let (window, id) = keys::request_entry(&key).unwrap();
        let read = PendingRead::decode(unstored(&value).unwrap()).unwrap().0;
        if !recorded.contains_key(&window) {
            continue;
        }
        let proof = roots::cut_proof(&snapshots[0], agent, id).unwrap();
        for snapshot in &snapshots[1..] {
            assert_eq!(
                roots::cut_proof(snapshot, agent, id).unwrap(),
                proof,
                "{id:?}"
            );
        }
        let Some(proof) = proof else {
            continue;
        };
        assert_eq!(
            (proof.window, proof.version),
            (window, recorded[&window]),
            "agent {}: {id:?}'s cut",
            agent.0
        );
        if let Some((root, _)) = roots.get(&window) {
            assert_eq!(proof.agent_root, *root, "the root at cut({window})");
        }
        assert_eq!(
            proof
                .rows
                .iter()
                .map(|(row, _)| row.clone())
                .collect::<Vec<_>>(),
            read.rows
        );
        let claims: Vec<(Vec<u8>, Option<Hash>)> = proof
            .rows
            .iter()
            .map(|(row, held)| {
                let held = held
                    .as_ref()
                    .map(|(salt, value)| vos_tree::value_hash(&Blake2b, salt, value));
                (row.clone(), held)
            })
            .collect();
        vos_tree::verify_encoded(&Blake2b, &proof.rows_proof, &proof.agent_root, &claims).unwrap();
        proven += 1;
    }
    assert!(proven > 0, "agent {}: no request proved", agent.0);
}

/// The exactly-once run with window cuts, its replicas' states equal
/// though each holds its own undo rows. With `CUTS_FULL` set, the run
/// tours workflows as well, as the checker loop runs it.
#[test]
fn cuts_apply_once_and_replicas_agree_through_failures() {
    let cuts = Cuts {
        undo_held: Mutex::new(0),
    };
    let rounds = std::env::var_os("CUTS_FULL").map(|_| Rounds::load());
    exactly_once(Mode::OneAtATime, 0x5eed_0612, rounds, Some(&cuts));
}
