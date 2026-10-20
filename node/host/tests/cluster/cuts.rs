//! Window cuts on replicated agents: the leader's `Cut` marker for an idle
//! agent, timed at its own clock; a fast clock's jump cutting several
//! windows at one version; and reads at a cut, the reader's workflows'
//! (`agent/test-actors/reader`): a replica down across a cut, and a leader
//! change between a cut and its close, each finding every replica holding
//! the cut's proofs; and a read served by its leader and stated.
//!
//! Each space here has windows of an hour, the longest a venue registers,
//! its first boundary `B_0` most of an hour after the cluster starts, so
//! no boundary passes however slowly a loaded machine runs a test: the
//! tests move nodes' clocks across boundaries by their offsets. A cut, its
//! build and its proofs are the model's terms (`tests/cuts/model.rs`); the
//! close is the representative's `Closed` (`representative.rs`). With no
//! representative, no read is served, so "before the close" is any time
//! after the cut.

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::time::Duration;

use vos_checker::programs::{actor, method, package, table_tag};
use vos_node::roots::{self, AgentStore, CutProof, ReadRow};
use vos_node::store::EntryKind;
use vos_node::{Node, Reply};
use vos_tree::{Blake2b, Hash, NodeStore};
use vos_venue::VenueClient;
use vos_wire::batch::Request;
use vos_wire::ids::{AgentId, InstanceId, MapId, MethodId, RequestId};
use vos_wire::keys::{self, Transform};
use vos_wire::peer::NodeNumber;
use vos_wire::records::{PendingRead, unstored, unversioned};
use vos_wire::result::{Outcome, WorkResult};
use vos_wire::vos_anchor::MAX_LENGTH_MS;
use vos_wire::{Decode, Encode, WindowClock};

use crate::common::{ALICE, Cluster, Rows, compacting, log_start, wait_until};
use crate::representative::{Anchoring, delay, rep_root};

/// A space's clock of hour-long windows, now a minute into window 0.
pub(crate) fn clock() -> WindowClock {
    WindowClock {
        origin_ms: vos_node::wall_clock() - 60_000,
        length_ms: MAX_LENGTH_MS,
    }
}

/// Set node `number`'s clock to read `at` about now.
pub(crate) fn set_clock(cluster: &Cluster, number: NodeNumber, at: u64) {
    let own = vos_node::wall_clock() + u64::from(number) * 7;
    cluster.offsets[usize::from(number) - 1].store(at as i64 - own as i64, Ordering::SeqCst);
}

/// The cuts `node` holds of `agent`: each window's version.
pub(crate) fn cuts(node: &Node, agent: AgentId) -> BTreeMap<u64, u64> {
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
pub(crate) fn version(node: &Node, agent: AgentId) -> u64 {
    vos_checker::applied(node.store(), agent, &keys::version()).unwrap_or(0)
}

/// `agent`'s applied index as `node`'s store holds it: the index written
/// in the commit of its apply. The node's own count of it moves once that
/// commit returns, so a row an apply wrote can be read before it does.
fn stored_applied(node: &Node, agent: AgentId) -> u64 {
    node.store().snapshot().applied(agent).unwrap().unwrap_or(0)
}

/// The work results of `agent`'s log on `node` past index `after`, through
/// its applied index in the store: each with its index.
pub(crate) fn results(node: &Node, agent: AgentId, after: u64) -> Vec<(u64, WorkResult)> {
    let through = stored_applied(node, agent);
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
    let agent = reader_agent(&cluster, &[1, 2, 3]);
    let leader = cluster.leader(agent);
    let node = cluster.node(leader);
    let applied = stored_applied(node, agent);
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
    let applied = stored_applied(node, agent);

    set_clock(&cluster, leader, b0 + 500);
    let reading = cluster.clock(leader);
    // The cut row may show in the store before the node's applied index
    // passes the marker: wait for both.
    wait_until("the leader's replica records cut(0)", || {
        cuts(node, agent).contains_key(&0) && !results(node, agent, applied).is_empty()
    });
    let after = cluster.clock(leader);
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
    let marked = stored_applied(node, agent);
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
    let applied = stored_applied(node, agent);
    let boundary = WindowClock::DEFAULT
        .boundary(WindowClock::DEFAULT.window(cluster.clock(leader)).unwrap())
        .unwrap();
    for number in 1..=3 {
        set_clock(&cluster, number, boundary + 1_000);
    }
    std::thread::sleep(Duration::from_secs(2));
    // A marker is an empty result; the install's, should a loaded host
    // apply it only now, is not.
    let appended = results(node, agent, applied);
    assert!(
        appended.iter().all(|(_, result)| !result.steps.is_empty()),
        "no marker: {appended:?}"
    );
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
    let ahead = clock.boundary(2).unwrap() + MAX_LENGTH_MS / 2;
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

/// The reader, installed beside the counter.
pub(crate) const READER: InstanceId = InstanceId(2);

/// An agent on `replicas` with the counter and the reader installed.
pub(crate) fn reader_agent(cluster: &Cluster, replicas: &[NodeNumber]) -> AgentId {
    let agent = cluster.counter_agent(replicas);
    cluster.install_package(agent, READER, &package("reader"));
    agent
}

/// The reader's method `name`.
pub(crate) fn reader(name: &str) -> MethodId {
    method(&actor("reader"), name)
}

/// The reader's committed map, `entries`.
pub(crate) fn entries() -> MapId {
    MapId {
        instance: READER,
        tag: table_tag("entries"),
        transform: Transform::Hashed,
    }
}

/// Request `sequence` of the cluster's session at `agent`: 25 puts and
/// deletes in the reader's committed map, over 300 keys that come back.
pub(crate) fn writes(cluster: &Cluster, agent: AgentId, sequence: u64) -> Request {
    let writes: Vec<(u64, Option<u64>)> = (0..25u64)
        .map(|index| {
            let key = (sequence * 37 + index * 11) % 300;
            (key, (key % 7 != sequence % 7).then_some(sequence))
        })
        .collect();
    Request {
        session: cluster.session(agent),
        sequence,
        caller: ALICE,
        instance: READER,
        method: reader("set_entries"),
        arguments: writes.encode(),
    }
}

/// `request` at `agent`'s leader, followed as it moves: its outcome.
pub(crate) fn call(cluster: &Cluster, agent: AgentId, request: Request) -> Outcome {
    let sequence = request.sequence;
    match cluster.call_at_leader(agent, request) {
        Ok(Reply::Ran(outcome)) => outcome,
        other => panic!("sequence {sequence}: {other:?}"),
    }
}

/// Each request of `sequences` at `agent`'s leader, followed as it moves.
pub(crate) fn write(cluster: &Cluster, agent: AgentId, sequences: std::ops::RangeInclusive<u64>) {
    for sequence in sequences {
        let outcome = call(cluster, agent, writes(cluster, agent, sequence));
        assert!(
            matches!(outcome, Outcome::Done(_)),
            "sequence {sequence}: {outcome:?}"
        );
    }
}

/// The agent's committed rows on `node` once its root is built at its
/// version: the root, the version, and each row's salt and bare value.
pub(crate) type Settled = (Hash, u64, BTreeMap<Vec<u8>, ([u8; 16], Vec<u8>)>);

pub(crate) fn settled(node: &Node, agent: AgentId) -> Settled {
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

/// A read of the current window by the reader's workflow `sum_at_cut`,
/// started by request `sequence`, once every running replica holds its
/// request: sixteen rows of the reader's committed map, twelve the writes
/// reach and four they never do.
pub(crate) fn ask(cluster: &Cluster, agent: AgentId, sequence: u64) -> (RequestId, PendingRead) {
    let (id, read, _) = ask_keys(cluster, agent, sequence);
    (id, read)
}

/// [`ask`], and the keys the read names, its kernel's arguments.
pub(crate) fn ask_keys(
    cluster: &Cluster,
    agent: AgentId,
    sequence: u64,
) -> (RequestId, PendingRead, Vec<u64>) {
    let leader = cluster.node(cluster.leader(agent));
    let map = entries();
    let present: Vec<u64> = settled(leader, agent)
        .2
        .into_keys()
        .filter_map(|row| {
            let transformed = row.strip_prefix(&keys::committed_rows(&map)[..])?;
            let raw = Transform::Hashed.raw(transformed)?;
            Some(u64::from_be_bytes(raw.try_into().ok()?))
        })
        .take(12)
        .collect();
    assert_eq!(present.len(), 12, "twelve rows written");
    let keys: Vec<u64> = present.iter().copied().chain(1_000..1_004).collect();
    let start = Request {
        session: cluster.session(agent),
        sequence,
        caller: ALICE,
        instance: READER,
        method: reader("sum_at_cut"),
        arguments: keys.encode(),
    };
    let Outcome::Started(workflow) = call(cluster, agent, start) else {
        panic!("the read did not start");
    };
    let id = RequestId {
        workflow,
        awaits: 0,
    };
    let mut rows: Vec<Vec<u8>> = keys
        .iter()
        .map(|key| keys::committed(&map, &Transform::Hashed.apply(&key.to_be_bytes())))
        .collect();
    rows.sort();
    let read = PendingRead {
        instance: READER,
        rows,
    };
    for (_, node) in cluster.running() {
        if node.applied(agent).is_none() {
            continue;
        }
        wait_until("every replica holds the request", || {
            node.store()
                .snapshot()
                .get(agent, &keys::request(0, id))
                .unwrap()
                .is_some()
        });
    }
    (id, read, keys)
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
        let mut cluster = Cluster::in_space(3, Some(clock), move |number, config| {
            if by_snapshot {
                compacting(number, config);
            }
        });
        let agent = reader_agent(&cluster, &[1, 2, 3]);
        write(&cluster, agent, 1..=10);
        let (_, follower) = cluster.leader_and_follower(agent);
        let stopped_at = cluster.node(follower).applied(agent).unwrap();
        cluster.stop(follower);
        let (id, _) = ask(&cluster, agent, 11);
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
    let mut cluster = Cluster::in_space(3, Some(clock), |_, _| {});
    let agent = reader_agent(&cluster, &[1, 2, 3]);
    write(&cluster, agent, 1..=20);
    let (id, read) = ask(&cluster, agent, 21);
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
    wait_until("every replica builds the same root", || {
        let roots: Vec<_> = cluster
            .running()
            .map(|(_, node)| roots::agent_root(&node.store().snapshot(), agent).ok())
            .collect();
        roots.iter().all(Option::is_some) && roots.windows(2).all(|pair| pair[0] == pair[1])
    });
}

/// A read served by its leader. The reader's workflow reads sixteen rows of
/// its committed map at window 0's cut; the clocks pass `B_0`; the agent's
/// leader reports its root at the cut to the space's representative, and
/// once the clocks pass `B_0 + D`, the representative's own cut closes the
/// window: its leader anchors `S_0` at the venue and sends the agent its
/// path. The agent's leader then serves the rows with their proof and the
/// path, and the workflow's step runs the kernel on them: it ends with the
/// sum of the values at the cut, though later writes rewrote them, and its
/// step states the read: the window, the reader and the keys as public
/// arguments, and `S_0` over the representative's root at its cut, the
/// root the venue holds anchored. Every replica then holds neither the
/// request nor its proof, and the same rows.
#[test]
fn a_read_at_a_cut_is_served_by_its_leader() {
    let clock = clock();
    let b0 = clock.boundary(0).unwrap();
    let anchoring = Anchoring::new();
    let cluster = Cluster::in_space(3, Some(clock), anchoring.tuning());
    anchoring.register(&cluster);
    let representative = cluster.representative(&[1, 2, 3]);
    let agent = reader_agent(&cluster, &[1, 2, 3]);
    write(&cluster, agent, 1..=20);
    let (id, read) = ask(&cluster, agent, 21);
    let (_, at_cut, values) = settled(cluster.node(cluster.leader(agent)), agent);
    let sum = read
        .rows
        .iter()
        .filter_map(|row| values.get(row))
        .map(|(_, value)| u64::decode(value).unwrap().0)
        .fold(0u64, u64::wrapping_add);
    let leader = cluster.leader(agent);
    let applied = stored_applied(cluster.node(leader), agent);
    anchoring.set_clocks(&cluster, b0 + 1_000);
    write(&cluster, agent, 22..=30);
    anchoring.set_clocks(&cluster, b0 + delay(&clock) + 1_000);
    let node = cluster.node(leader);
    let mut ended = None;
    wait_until("the read is served and its workflow ends", || {
        let record: Option<vos_wire::records::Workflow> =
            vos_checker::applied(node.store(), agent, &keys::workflow(id.workflow));
        ended = record.and_then(|record| match record.state {
            vos_wire::records::WorkflowState::Ended(outcome) => Some(outcome),
            _ => None,
        });
        ended.is_some()
    });
    assert_eq!(ended, Some(Outcome::Done(sum.encode())));
    let attest = results(node, agent, applied)
        .into_iter()
        .flat_map(|(_, result)| result.steps)
        .find_map(|step| match step {
            vos_wire::result::Step::Ran(run)
                if run.input == (vos_wire::result::InputRef::Resume { request: id }) =>
            {
                run.attests.into_iter().next()
            }
            _ => None,
        })
        .expect("the read's attest");
    let rep_root = rep_root(&cluster, representative, 0);
    let keys_read: Vec<u64> = vos_wire::Decode::decode(&attest.witness_input).unwrap().0;
    let mut public_args = (agent, READER).encode();
    public_args.extend(keys_read.encode());
    let stated = vos_wire::vos_anchor::RootRead {
        kind: vos_wire::vos_anchor::RootKind::Space,
        space: cluster.space.id(),
        window: 0,
        root: vos_wire::vos_anchor::space_root(&cluster.space.id(), 0, &rep_root),
    };
    assert_eq!(attest.window, Some(0));
    assert_eq!(attest.output, sum.encode());
    assert_eq!(attest.public_args, public_args);
    assert_eq!(attest.roots, [stated]);
    assert!(anchoring.venue.anchored(&stated), "S_0 anchored");
    assert_eq!(cuts(node, agent).get(&0), Some(&at_cut));
    for (_, node) in cluster.running() {
        wait_until("every replica answers the request", || {
            let snapshot = node.store().snapshot();
            snapshot
                .get(agent, &keys::request(0, id))
                .unwrap()
                .is_none()
                && roots::cut_proof(&snapshot, agent, id).unwrap().is_none()
        });
    }
    same_state(&cluster, agent);
}

/// `agent`'s replicated rows on `node` ([`keys::is_replicated`]) and its
/// applied index, from one store snapshot.
pub(crate) fn replicated(node: &Node, agent: AgentId) -> (Option<u64>, Rows) {
    let snapshot = node.store().snapshot();
    let rows = [[0x00u8], [0x01], [0x03]]
        .iter()
        .flat_map(|prefix| snapshot.scan(agent, prefix, None).map(Result::unwrap))
        .filter(|(key, _)| keys::is_replicated(key))
        .collect();
    (snapshot.applied(agent).unwrap(), rows)
}

/// Every running replica holds the same replicated rows at the same
/// applied index.
pub(crate) fn same_state(cluster: &Cluster, agent: AgentId) {
    wait_until("every replica holds the same rows", || {
        let views: Vec<_> = cluster
            .running()
            .map(|(_, node)| replicated(node, agent))
            .collect();
        views.len() > 1 && views.windows(2).all(|pair| pair[0] == pair[1])
    });
}
