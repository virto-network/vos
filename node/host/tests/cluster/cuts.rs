//! Window cuts on replicated agents: the leader's `Cut` marker for an idle
//! agent, timed at its own clock; a fast clock's jump cutting several
//! windows at one version; and a leader change between a cut and its
//! close, which finds every replica holding the cut's proofs.
//!
//! Each space here has windows of two minutes, the shortest a venue
//! registers, with a boundary `B_0` some seconds after the cluster starts;
//! the tests move nodes' clocks across boundaries by their offsets rather
//! than wait. A cut, its build and its proofs are the model's terms
//! (`tests/cuts/model.rs`); the close is the representative's `Closed`,
//! which no node sends yet, so "before the close" is any time after the
//! cut.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vos_checker::programs::table_tag;
use vos_node::roots::{self, AgentStore, CutProof, ReadRow};
use vos_node::store::EntryKind;
use vos_node::{CallError, Hooks, Node, Reply};
use vos_tree::{Blake2b, Hash, NodeStore};
use vos_wire::batch::Request;
use vos_wire::ids::{AgentId, MapId, RequestId, WorkflowId};
use vos_wire::keys;
use vos_wire::peer::NodeNumber;
use vos_wire::records::{PendingRead, unstored, unversioned};
use vos_wire::result::{Outcome, WorkResult};
use vos_wire::vos_anchor::MIN_LENGTH_MS;
use vos_wire::{Decode, Encode, WindowClock};

use crate::common::{ALICE, COUNTER, Cluster, Rows, compacting, log_start, wait_until};

/// How far after the cluster starts its first boundary falls.
const LEAD_MS: u64 = 30_000;

/// A space's clock of two-minute windows whose first boundary, `B_0`, is
/// `LEAD_MS` from now.
fn clock() -> WindowClock {
    WindowClock {
        origin_ms: vos_node::wall_clock() + LEAD_MS - MIN_LENGTH_MS,
        length_ms: MIN_LENGTH_MS,
    }
}

/// Each node's clock as the cluster sets it: the wall's, its few
/// milliseconds of skew, and its offset.
fn clock_of(cluster: &Cluster, number: NodeNumber) -> u64 {
    let offset = cluster.offsets[usize::from(number) - 1].load(Ordering::SeqCst);
    (vos_node::wall_clock() + u64::from(number) * 7).saturating_add_signed(offset)
}

/// Set node `number`'s clock to read `at` about now.
fn set_clock(cluster: &Cluster, number: NodeNumber, at: u64) {
    let own = vos_node::wall_clock() + u64::from(number) * 7;
    cluster.offsets[usize::from(number) - 1].store(at as i64 - own as i64, Ordering::SeqCst);
}

/// The cuts `node` holds of `agent`: each window's version.
fn cuts(node: &Node, agent: AgentId) -> BTreeMap<u64, u64> {
    node.store()
        .snapshot()
        .scan(agent, &keys::cuts(), None)
        .map(|row| {
            let (key, value) = row.unwrap();
            let version = u64::decode(unstored(&value).unwrap()).unwrap().0;
            (keys::cut_entry(&key).unwrap(), version)
        })
        .collect()
}

/// `agent`'s state version on `node`.
fn version(node: &Node, agent: AgentId) -> u64 {
    vos_checker::applied(node.store(), agent, &keys::version()).unwrap_or(0)
}

/// The work results of `agent`'s log on `node` past index `after`, through
/// its applied index: each with its index.
fn results(node: &Node, agent: AgentId, after: u64) -> Vec<(u64, WorkResult)> {
    let through = node.applied(agent).unwrap_or(0);
    (after + 1..=through)
        .filter_map(|index| {
            let entry = node.store().log_entry(agent, index).unwrap()?;
            if entry.kind != EntryKind::Result {
                return None;
            }
            let result = WorkResult::decode(&entry.body).ok()?.0;
            Some((index, result))
        })
        .collect()
}

/// The leader's `Cut` marker for an idle agent. While the leader's clock
/// trails `B_0` it appends none, though every follower's clock is past it,
/// and an input's result is timed at its clock, before `B_0`: no cut is
/// recorded. Once its own clock passes `B_0` it appends one
/// empty work result, timed at its clock (at or past `B_0`, never `B_0`
/// itself when its clock is later), and every replica records `cut(0)` at
/// the agent's version before it. No second marker comes in the same
/// window.
#[test]
fn an_idle_agents_leader_appends_one_marker_at_its_own_clock() {
    let clock = clock();
    let b0 = clock.boundary(0).unwrap();
    let cluster = Cluster::in_space(3, Some(clock), |_, _| {});
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.leader(agent);
    let node = cluster.node(leader);
    let applied = node.applied(agent).unwrap();
    for number in (1..=3).filter(|number| *number != leader) {
        set_clock(&cluster, number, b0 + 2_000);
    }
    std::thread::sleep(Duration::from_secs(1));
    assert_eq!(cluster.leader(agent), leader, "the leader stayed");
    assert!(
        cuts(node, agent).is_empty(),
        "a trailing leader cuts nothing"
    );
    assert!(results(node, agent, applied).is_empty(), "nor appends");
    // An input: its result timed at the leader's clock, before `B_0`.
    write(&cluster, agent, 1..=1);
    let written = results(node, agent, applied);
    let [(_, result)] = &written[..] else {
        panic!("one result: {written:?}");
    };
    assert!(result.time < b0, "timed at the trailing leader's clock");
    assert!(cuts(node, agent).is_empty(), "and cutting nothing");
    let before = version(node, agent);
    let applied = node.applied(agent).unwrap();

    set_clock(&cluster, leader, b0 + 500);
    let reading = clock_of(&cluster, leader);
    wait_until("the leader's replica records cut(0)", || {
        cuts(node, agent).contains_key(&0)
    });
    let after = clock_of(&cluster, leader);
    assert_eq!(cuts(node, agent), BTreeMap::from([(0, before)]));
    let appended = results(node, agent, applied);
    let [(_, marker)] = &appended[..] else {
        panic!("one result appended: {appended:?}");
    };
    assert!(marker.steps.is_empty(), "the marker is an empty result");
    assert_eq!(marker.version, before);
    assert!(
        b0.max(reading) <= marker.time && marker.time <= after,
        "the marker timed at the leader's clock: {} not in {}..={after}",
        marker.time,
        b0.max(reading)
    );
    for number in 1..=3 {
        wait_until("every replica records the cut", || {
            cuts(cluster.node(number), agent) == BTreeMap::from([(0, before)])
        });
    }
    let marked = node.applied(agent).unwrap();
    std::thread::sleep(Duration::from_secs(1));
    assert!(
        results(node, agent, marked).is_empty(),
        "one marker a window"
    );
}

/// An agent of no space, its nodes' space founded with no genesis, runs no
/// cuts: its leader appends no marker as its clock passes a boundary of
/// the default clock, and no replica records a cut.
#[test]
fn an_agent_of_no_space_gets_no_marker() {
    let cluster = Cluster::in_space(3, None, |_, _| {});
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.leader(agent);
    let node = cluster.node(leader);
    let applied = node.applied(agent).unwrap();
    let boundary = WindowClock::DEFAULT
        .boundary(
            WindowClock::DEFAULT
                .window(clock_of(&cluster, leader))
                .unwrap(),
        )
        .unwrap();
    for number in 1..=3 {
        set_clock(&cluster, number, boundary + 1_000);
    }
    std::thread::sleep(Duration::from_secs(2));
    assert!(results(node, agent, applied).is_empty(), "no marker");
    for number in 1..=3 {
        assert!(cuts(cluster.node(number), agent).is_empty());
    }
}

/// A leader's clock jumping Δ ahead, from window 0 into window 3, cuts
/// windows 0 to 2 at one version, the agent's before the marker its clock
/// times past them; every replica records the same. The clock stepping
/// back cuts nothing more: batch time stands at the mark until real time
/// passes it.
#[test]
fn a_leaders_clock_jumping_ahead_cuts_every_window_it_passes_at_one_version() {
    let clock = clock();
    let cluster = Cluster::in_space(3, Some(clock), |_, _| {});
    let agent = cluster.counter_agent(&[1, 2, 3]);
    let leader = cluster.leader(agent);
    let node = cluster.node(leader);
    let before = version(node, agent);
    let ahead = clock.boundary(2).unwrap() + MIN_LENGTH_MS / 2;
    set_clock(&cluster, leader, ahead);
    wait_until("the leader's replica records cut(2)", || {
        cuts(node, agent).contains_key(&2)
    });
    let jumped = BTreeMap::from([(0, before), (1, before), (2, before)]);
    for number in 1..=3 {
        wait_until("every replica records the same cuts", || {
            cuts(cluster.node(number), agent) == jumped
        });
    }
    let mark: u64 = vos_checker::applied(node.store(), agent, &keys::batch_time()).unwrap();
    assert!(mark >= ahead, "the mark at the leader's clock");
    cluster.offsets[usize::from(leader) - 1].store(0, Ordering::SeqCst);
    std::thread::sleep(Duration::from_secs(1));
    for number in 1..=3 {
        assert_eq!(cuts(cluster.node(number), agent), jumped, "nothing more");
        let held: u64 =
            vos_checker::applied(cluster.node(number).store(), agent, &keys::batch_time()).unwrap();
        assert!(held >= mark, "batch time never goes back");
    }
}

/// The request hook: the leader's batches record `request` while armed,
/// for the agent it names.
#[derive(Default)]
struct Asking {
    armed: AtomicBool,
    request: Mutex<Option<(AgentId, RequestId, PendingRead)>>,
}

impl Hooks for Asking {
    fn request_at_cut(&self, agent: AgentId, _: u64) -> Option<(RequestId, PendingRead)> {
        if !self.armed.load(Ordering::SeqCst) {
            return None;
        }
        let held = self.request.lock().unwrap();
        let (asker, id, read) = held.as_ref()?;
        (*asker == agent).then(|| (*id, read.clone()))
    }
}

/// The counter's committed map, `entries`, of the transform its rows on
/// `node` name.
fn entries(node: &Node, agent: AgentId) -> MapId {
    let tag = table_tag("entries");
    node.store()
        .snapshot()
        .scan(agent, &keys::instance_committed(COUNTER), None)
        .find_map(|row| {
            let (key, _) = row.unwrap();
            keys::committed_entry(&key)
                .map(|(map, _)| map)
                .filter(|map| map.tag == tag)
        })
        .expect("a value row of the committed map")
}

/// Request `sequence` of the cluster's session: 25 puts and deletes in the
/// committed map, over 300 keys that come back.
fn writes(cluster: &Cluster, sequence: u64) -> Request {
    let writes: Vec<(u64, Option<u64>)> = (0..25u64)
        .map(|index| {
            let key = (sequence * 37 + index * 11) % 300;
            (key, (key % 7 != sequence % 7).then_some(sequence))
        })
        .collect();
    Request {
        session: cluster.session,
        sequence,
        caller: ALICE,
        instance: COUNTER,
        method: cluster.programs.method("set_entries"),
        arguments: writes.encode(),
    }
}

/// Each request of `sequences` at `agent`'s leader, followed as it moves.
fn write(cluster: &Cluster, agent: AgentId, sequences: std::ops::RangeInclusive<u64>) {
    for sequence in sequences {
        let mut backoff = Duration::from_millis(10);
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            let node = cluster.node(cluster.leader(agent));
            match smol::block_on(node.call(agent, writes(cluster, sequence))) {
                Ok(Reply::Ran(Outcome::Done(_))) => break,
                Err(CallError::NotLeader(_) | CallError::TimedOut) if Instant::now() < until => {
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_millis(500));
                }
                other => panic!("sequence {sequence}: {other:?}"),
            }
        }
    }
}

/// The agent's committed rows on `node` once its root is built at its
/// version: the root, the version, and each row's salt and bare value.
type Settled = (Hash, u64, BTreeMap<Vec<u8>, ([u8; 16], Vec<u8>)>);

fn settled(node: &Node, agent: AgentId) -> Settled {
    let mut settled = None;
    wait_until("the root built at the agent's version", || {
        let snapshot = node.store().snapshot();
        let at = version(node, agent);
        let Ok((root, built)) = roots::agent_root(&snapshot, agent) else {
            return false;
        };
        if built != at {
            return false;
        }
        let tree = AgentStore::open(&snapshot, agent).unwrap();
        let rows = snapshot
            .scan(agent, &keys::committed_all(), None)
            .map(|row| {
                let (key, stored) = row.unwrap();
                let (_, value) = unversioned(unstored(&stored).unwrap()).unwrap();
                let leaf = tree.leaf(&key).unwrap().expect("a leaf");
                (key, (leaf.salt, value.to_vec()))
            })
            .collect();
        settled = Some((root, built, rows));
        true
    });
    settled.unwrap()
}

/// A pending request of the current window, recorded by the leader's batch
/// of request `sequence`, once every running replica holds it: sixteen
/// rows of the counter's committed map, twelve the writes reach and four
/// they never do.
fn ask(
    cluster: &Cluster,
    agent: AgentId,
    asking: &Asking,
    sequence: u64,
) -> (RequestId, PendingRead) {
    let leader = cluster.node(cluster.leader(agent));
    let map = entries(leader, agent);
    let present: Vec<Vec<u8>> = settled(leader, agent)
        .2
        .into_keys()
        .filter(|row| row.starts_with(&keys::committed_rows(&map)))
        .take(12)
        .collect();
    let mut rows = present.clone();
    for row in present.iter().take(4) {
        let mut absent = row.clone();
        absent[keys::COMMITTED_PREFIX] ^= 0xff;
        rows.push(absent);
    }
    rows.sort();
    rows.dedup();
    let id = RequestId {
        workflow: WorkflowId(1),
        awaits: 0,
    };
    let read = PendingRead {
        instance: COUNTER,
        rows,
    };
    *asking.request.lock().unwrap() = Some((agent, id, read.clone()));
    asking.armed.store(true, Ordering::SeqCst);
    write(cluster, agent, sequence..=sequence);
    for (_, node) in cluster.running() {
        wait_until("every replica holds the request", || {
            node.store()
                .snapshot()
                .get(agent, &keys::request(0, id))
                .unwrap()
                .is_some()
        });
    }
    asking.armed.store(false, Ordering::SeqCst);
    (id, read)
}

/// A replica down across a cut builds it on its return, by the log or by
/// a snapshot of the leader's state: the request's proof and the root at
/// the cut the same bytes as every other replica's, though the rows it
/// reads were rewritten after the cut before the replica came back.
#[test]
fn a_replica_down_across_a_cut_holds_its_proofs_on_return() {
    for by_snapshot in [false, true] {
        let clock = clock();
        let b0 = clock.boundary(0).unwrap();
        let asking = Arc::new(Asking::default());
        let hooks = Arc::clone(&asking);
        let mut cluster = Cluster::in_space(3, Some(clock), move |number, config| {
            config.hooks = hooks.clone();
            if by_snapshot {
                compacting(number, config);
            }
        });
        let agent = cluster.counter_agent(&[1, 2, 3]);
        write(&cluster, agent, 1..=10);
        let (_, follower) = cluster.leader_and_follower(agent);
        let stopped_at = cluster.node(follower).applied(agent).unwrap();
        cluster.stop(follower);
        let (id, _) = ask(&cluster, agent, &asking, 11);
        write(&cluster, agent, 12..=20);
        for number in 1..=3 {
            set_clock(&cluster, number, b0 + 1_000);
        }
        write(&cluster, agent, 21..=60);
        let leading = cluster.leader(agent);
        let node = cluster.node(leading);
        let mut proof = None;
        wait_until("the leader's replica builds the cut", || {
            proof = roots::cut_proof(&node.store().snapshot(), agent, id).unwrap();
            proof.is_some()
        });
        let root = roots::cut_root(&node.store().snapshot(), agent, 0).unwrap();
        if by_snapshot {
            cluster.compacted_past(leading, agent, stopped_at);
        }
        cluster.start(follower);
        let back = cluster.node(follower);
        wait_until("the replica returns and builds the cut", || {
            back.applied(agent) >= cluster.node(leading).applied(agent)
                && roots::cut_proof(&back.store().snapshot(), agent, id)
                    .unwrap()
                    .is_some()
        });
        let snapshot = back.store().snapshot();
        assert_eq!(roots::cut_proof(&snapshot, agent, id).unwrap(), proof);
        assert_eq!(roots::cut_root(&snapshot, agent, 0).unwrap(), root);
        if by_snapshot {
            assert!(log_start(back, agent) > stopped_at, "installed a snapshot");
        }
        same_state(&cluster, agent);
    }
}

/// A leader change between a cut and its close. A pending request of
/// window 0 reads sixteen rows of the counter's committed map; the clocks
/// pass `B_0`; every replica records `cut(0)` at the version the agent
/// stood at, builds there, and persists the request's proof: the rows as
/// they stood at the cut, with their salts, under one proof against the
/// root at the cut, the same bytes on every replica. Later writes rewrite
/// those rows. Then the leader stops: the new leader's replica, and the
/// third, still hold the proof unchanged, of window 0 (no re-cut), and the
/// old leader's, restarted, holds it too.
#[test]
fn a_leader_change_between_a_cut_and_its_close_keeps_its_proofs() {
    let clock = clock();
    let b0 = clock.boundary(0).unwrap();
    let asking = Arc::new(Asking::default());
    let hooks = Arc::clone(&asking);
    let mut cluster = Cluster::in_space(3, Some(clock), move |_, config| {
        config.hooks = hooks.clone();
    });
    let agent = cluster.counter_agent(&[1, 2, 3]);
    write(&cluster, agent, 1..=20);
    let (id, read) = ask(&cluster, agent, &asking, 21);
    write(&cluster, agent, 22..=30);

    // The state at the cut: nothing applies between it and `B_0`.
    let (root, at_cut, values) = settled(cluster.node(cluster.leader(agent)), agent);
    for number in 1..=3 {
        set_clock(&cluster, number, b0 + 1_000);
    }
    write(&cluster, agent, 31..=31);
    let proofs: Vec<CutProof> = (1..=3)
        .map(|number| {
            let node = cluster.node(number);
            let mut proof = None;
            wait_until("every replica builds the cut and its proof", || {
                proof = roots::cut_proof(&node.store().snapshot(), agent, id).unwrap();
                proof.is_some()
            });
            assert_eq!(cuts(node, agent).get(&0), Some(&at_cut), "cut(0)");
            assert_eq!(
                roots::cut_root(&node.store().snapshot(), agent, 0).unwrap(),
                Some((root, at_cut))
            );
            proof.unwrap()
        })
        .collect();
    let proof = proofs[0].clone();
    assert!(
        proofs.iter().all(|other| other.encode() == proof.encode()),
        "the same bytes on every replica"
    );
    assert_eq!(
        (proof.window, proof.version, proof.agent_root),
        (0, at_cut, root)
    );
    let expected: Vec<ReadRow> = read
        .rows
        .iter()
        .map(|row| (row.clone(), values.get(row).cloned()))
        .collect();
    assert_eq!(proof.rows, expected, "the rows as they stood at the cut");
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
    vos_tree::verify_encoded(&Blake2b, &proof.rows_proof, &root, &claims).unwrap();

    // After the cut, before the close: the rows rewritten, the leader
    // stopped.
    write(&cluster, agent, 32..=40);
    let old = cluster.leader(agent);
    cluster.stop(old);
    let new = cluster.leader(agent);
    assert_ne!(new, old);
    write(&cluster, agent, 41..=45);
    for number in (1..=3).filter(|number| *number != old) {
        let node = cluster.node(number);
        wait_until("the replica applies the new leader's writes", || {
            node.applied(agent) >= cluster.node(new).applied(agent)
        });
        let held = roots::cut_proof(&node.store().snapshot(), agent, id).unwrap();
        assert_eq!(held, Some(proof.clone()), "node {number} keeps the proof");
        assert!(
            node.store()
                .snapshot()
                .get(agent, &keys::request(0, id))
                .unwrap()
                .is_some(),
            "still pending at window 0"
        );
    }
    cluster.start(old);
    let restarted = cluster.node(old);
    wait_until("the old leader catches up", || {
        restarted.applied(agent) >= cluster.node(new).applied(agent)
    });
    assert_eq!(
        roots::cut_proof(&restarted.store().snapshot(), agent, id).unwrap(),
        Some(proof)
    );
    same_state(&cluster, agent);
}

/// `agent`'s replicated rows on `node` and its applied index, from one
/// store snapshot: its own but the dirty and seed rows its builder
/// consumes at its own pace, its instances', and its committed rows.
fn replicated(node: &Node, agent: AgentId) -> (Option<u64>, Rows) {
    let snapshot = node.store().snapshot();
    let local = [keys::dirty_prefix(), keys::seed_prefix()];
    let rows = [[0x00u8], [0x01], [0x03]]
        .iter()
        .flat_map(|prefix| snapshot.scan(agent, prefix, None).map(Result::unwrap))
        .filter(|(key, _)| !local.iter().any(|prefix| key.starts_with(prefix)))
        .collect();
    (snapshot.applied(agent).unwrap(), rows)
}

/// Every running replica holds the same replicated rows at the same
/// applied index.
fn same_state(cluster: &Cluster, agent: AgentId) {
    wait_until("every replica holds the same rows", || {
        let views: Vec<_> = cluster
            .running()
            .map(|(_, node)| replicated(node, agent))
            .collect();
        views.len() > 1 && views.windows(2).all(|pair| pair[0] == pair[1])
    });
}
