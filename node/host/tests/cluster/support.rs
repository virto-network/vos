//! What the cluster's cut and representative tests, and the carrier
//! audits, drive a space's reads with: the reader agent, its writes and
//! its reads at a cut ([`ask_in`]), the cuts and results a node holds; the
//! model venue a space anchors at ([`Anchoring`]), the representative's
//! roots and a read's outcome and attests.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use vos_checker::programs::{actor, method, package, table_tag};
use vos_node::roots::{self, AgentStore};
use vos_node::store::EntryKind;
use vos_node::{Config, Node, Reply};
use vos_tree::{Hash, NodeStore};
use vos_venue::vos_statement::{Refusal, Statement};
use vos_venue::{ModelVenue, SubmitOutcome, VenueClient};
use vos_wire::batch::Request;
use vos_wire::ids::{AgentId, InstanceId, MapId, MethodId, RequestId, Session};
use vos_wire::keys::{self, Transform};
use vos_wire::peer::NodeNumber;
use vos_wire::records::{PendingRead, Workflow, WorkflowState, unstored, unversioned};
use vos_wire::result::{Attest, InputRef, Outcome, Step, WorkResult};
use vos_wire::served::{representative_asks_of, representative_row};
use vos_wire::vos_anchor::{MAX_LENGTH_MS, RootKind, RootRead, VenueId};
use vos_wire::{Decode, Encode, WindowClock};

use crate::common::{ALICE, Cluster, Rows, wait_until};

/// A space's clock of hour-long windows, now a minute into window 0.
pub(crate) fn clock() -> WindowClock {
    WindowClock {
        origin_ms: vos_node::wall_clock() - 60_000,
        length_ms: MAX_LENGTH_MS,
    }
}

/// The cuts `node` holds of `agent`: each window's version.
pub(crate) fn cuts(node: &Node, agent: AgentId) -> BTreeMap<u64, u64> {
    vos_checker::cuts(&node.store().snapshot(), agent)
}

/// `agent`'s state version on `node`.
pub(crate) fn version(node: &Node, agent: AgentId) -> u64 {
    vos_checker::applied(node.store(), agent, &keys::version()).unwrap_or(0)
}

/// `agent`'s applied index as `node`'s store holds it: the index written
/// in the commit of its apply. The node's own count of it moves once that
/// commit returns, so a row an apply wrote can be read before it does.
pub(crate) fn stored_applied(node: &Node, agent: AgentId) -> u64 {
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

/// The reader, installed beside the counter.
pub(crate) const READER: InstanceId = InstanceId(2);

/// An agent on `replicas` with the counter and `actor` installed as
/// `instance`.
pub(crate) fn agent_with(
    cluster: &Cluster,
    replicas: &[NodeNumber],
    instance: InstanceId,
    actor: &str,
) -> AgentId {
    let agent = cluster.counter_agent(replicas);
    cluster.install_package(agent, instance, &package(actor));
    agent
}

/// An agent on `replicas` with the counter and the reader installed.
pub(crate) fn reader_agent(cluster: &Cluster, replicas: &[NodeNumber]) -> AgentId {
    agent_with(cluster, replicas, READER, "reader")
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
    ask_in(cluster, agent, cluster.session(agent), sequence, 0)
}

/// A session opened at `agent`'s leader's time now: the clocks have moved
/// past the cluster's session's expiry.
pub(crate) fn later(cluster: &Cluster, agent: AgentId) -> Session {
    let t0 = cluster.clock(cluster.leader(agent));
    Session {
        key: [1; 32],
        name: t0.to_le_bytes().repeat(2).try_into().unwrap(),
        t0,
    }
}

/// [`ask_keys`] as request `sequence` of `session`, asked in window
/// `window`.
pub(crate) fn ask_in(
    cluster: &Cluster,
    agent: AgentId,
    session: Session,
    sequence: u64,
    window: u64,
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
        session,
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
                .get(agent, &keys::request(window, id))
                .unwrap()
                .is_some()
        });
    }
    (id, read, keys)
}

/// `agent`'s replicated rows on `node` ([`keys::is_replicated`]) and its
/// applied index, from one store snapshot.
pub(crate) fn replicated(node: &Node, agent: AgentId) -> (Option<u64>, Rows) {
    let snapshot = node.store().snapshot();
    let rows = vos_checker::replicated(&snapshot, agent);
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

/// The venue the space anchors at, timed by its own clock, which the
/// tests move with the nodes'.
pub(crate) struct Anchoring {
    pub(crate) venue: Arc<ModelVenue>,
    clock: OffsetClock,
}

impl Anchoring {
    pub(crate) fn new() -> Self {
        let clock = OffsetClock::default();
        Self {
            venue: Arc::new(ModelVenue::new(VenueId([0x7e; 32]), clock.reader())),
            clock,
        }
    }

    /// Each node's config: anchoring at the venue.
    pub(crate) fn tuning(&self) -> impl Fn(NodeNumber, &mut Config) + Send + Sync + 'static {
        let venue: Arc<dyn VenueClient> = self.venue.clone();
        move |_, config| config.venue = Some(Arc::clone(&venue))
    }

    /// The cluster's space set registered at the venue, from window 0.
    pub(crate) fn register(&self, cluster: &Cluster) {
        self.venue
            .seed(cluster.space.genesis().expect("a genesis"), 0);
    }

    /// Every node's clock and the venue's set to read `at` about now.
    pub(crate) fn set_clocks(&self, cluster: &Cluster, at: u64) {
        cluster.set_clocks(at);
        self.set_venue(at);
    }

    /// The venue's clock set to read `at` about now.
    pub(crate) fn set_venue(&self, at: u64) {
        self.clock.set(at);
    }
}

/// A venue's clock: the wall's, moved by an offset the tests set.
#[derive(Clone, Default)]
pub(crate) struct OffsetClock(Arc<AtomicI64>);

impl OffsetClock {
    /// The clock set to read `at` about now.
    pub(crate) fn set(&self, at: u64) {
        self.0
            .store(at as i64 - vos_node::wall_clock() as i64, Ordering::SeqCst);
    }

    /// The clock, as a venue reads it.
    pub(crate) fn reader(&self) -> Arc<dyn Fn() -> u64 + Send + Sync> {
        let offset = Arc::clone(&self.0);
        Arc::new(move || {
            vos_node::wall_clock().saturating_add_signed(offset.load(Ordering::SeqCst))
        })
    }
}

/// The representative's delay `D` on `clock`.
pub(crate) fn delay(clock: &WindowClock) -> u64 {
    clock.representative().unwrap().origin_ms - clock.origin_ms
}

/// Whether `node`'s replica of the representative has closed `window`.
pub(crate) fn closed_on(node: &Node, representative: AgentId, window: u64) -> bool {
    vos_checker::applied::<(u64, Option<AgentId>)>(
        node.store(),
        representative,
        &keys::close_mark(),
    )
    .is_some_and(|(closed, _)| closed >= window)
}

/// Whether `representative`'s replica on `node` holds some agent's report
/// of `window`.
pub(crate) fn reported_on(node: &Node, representative: AgentId, window: u64) -> bool {
    node.store()
        .snapshot()
        .scan(representative, &representative_asks_of(window), None)
        .next()
        .is_some()
}

/// Every clock set a second past window `window`'s boundary, before its
/// close, by `set`; once every running replica of the space's
/// representative holds some agent's report of the window, past its close.
pub(crate) fn close_with(cluster: &Cluster, clock: &WindowClock, window: u64, set: impl Fn(u64)) {
    set(clock.boundary(window).unwrap() + 1_000);
    let representative = cluster
        .running()
        .find_map(|(_, node)| node.representative())
        .expect("a representative");
    wait_until(
        &format!("the representative holds a report of window {window}"),
        || {
            cluster
                .running()
                .filter(|(_, node)| node.applied(representative).is_some())
                .all(|(_, node)| reported_on(node, representative, window))
        },
    );
    set(past_close(clock, window));
}

/// A second past window `window`'s close on `clock`, `B_w + D`.
pub(crate) fn past_close(clock: &WindowClock, window: u64) -> u64 {
    clock.boundary(window).unwrap() + delay(clock) + 1_000
}

/// The representative's root at its cut of `window`, once every running
/// replica of it has built that cut: the same on each.
pub(crate) fn rep_root(cluster: &Cluster, representative: AgentId, window: u64) -> [u8; 32] {
    let mut root = None;
    wait_until("every replica of the representative builds its cut", || {
        let built: Vec<_> = cluster
            .running()
            .filter(|(_, node)| node.applied(representative).is_some())
            .map(|(_, node)| {
                roots::cut_root(&node.store().snapshot(), representative, window).unwrap()
            })
            .collect();
        let all = built.iter().all(Option::is_some) && !built.is_empty();
        if all {
            assert!(
                built.windows(2).all(|pair| pair[0] == pair[1]),
                "the replicas' roots at the cut differ: {built:?}"
            );
            root = built[0].map(|(root, _)| root);
        }
        all
    });
    root.unwrap()
}

/// How workflow `id` of `agent` ended, once it has, on a replica of it.
pub(crate) fn ended(cluster: &Cluster, agent: AgentId, id: RequestId) -> Outcome {
    let mut ended = None;
    wait_until("the read is served and its workflow ends", || {
        ended = cluster
            .running()
            .filter(|(_, node)| node.applied(agent).is_some())
            .find_map(|(_, node)| {
                let record: Workflow =
                    vos_checker::applied(node.store(), agent, &keys::workflow(id.workflow))?;
                match record.state {
                    WorkflowState::Ended(outcome) => Some(outcome),
                    _ => None,
                }
            });
        ended.is_some()
    });
    ended.unwrap()
}

/// The attests of the steps `request`'s `Resume`s made in `agent`'s log
/// on `node`, once its log holds one: the workflow's end, the last.
pub(crate) fn attests(node: &Node, agent: AgentId, request: RequestId) -> Vec<Attest> {
    let mut attests = Vec::new();
    wait_until("the replica applies the read's statement", || {
        attests = logged(node, agent, request);
        !attests.is_empty()
    });
    attests
}

/// The attests of the steps `request`'s `Resume`s made in `agent`'s log
/// on `node` so far.
pub(crate) fn logged(node: &Node, agent: AgentId, request: RequestId) -> Vec<Attest> {
    results(node, agent, 0)
        .into_iter()
        .flat_map(|(_, result)| result.steps)
        .filter_map(|step| match step {
            Step::Ran(run) if run.input == (InputRef::Resume { request }) => Some(run.attests),
            _ => None,
        })
        .flatten()
        .collect()
}

/// A node running `agent`.
pub(crate) fn replica(cluster: &Cluster, agent: AgentId) -> &Node {
    cluster
        .running()
        .find(|(_, node)| node.applied(agent).is_some())
        .map(|(_, node)| node)
        .expect("a replica")
}

/// Whether `representative`'s replica on `node` holds `agent`'s root at
/// `window`'s cut.
pub(crate) fn holds(node: &Node, representative: AgentId, agent: AgentId, window: u64) -> bool {
    node.store()
        .snapshot()
        .get(
            representative,
            &representative_row(agent, RootKind::Space, window),
        )
        .unwrap()
        .is_some()
}

/// The model venue's anchors, and statements taken once by id, every
/// root held unanchored while `hold` is set.
pub(crate) struct Judging {
    pub(crate) model: Arc<ModelVenue>,
    pub(crate) accepted: Mutex<BTreeSet<[u8; 32]>>,
    pub(crate) submissions: AtomicUsize,
    pub(crate) hold: AtomicBool,
}

impl Judging {
    /// The model venue `model`, its roots held unanchored from the start
    /// when `hold`.
    pub(crate) fn new(model: Arc<ModelVenue>, hold: bool) -> Self {
        Self {
            model,
            accepted: Mutex::default(),
            submissions: AtomicUsize::new(0),
            hold: AtomicBool::new(hold),
        }
    }
}

vos_venue::forward_venue!(Judging => model; forward [id, anchor, anchor_keys, status, held, time] {
    fn submit(&self, statement: &Statement, _: &[u8]) -> SubmitOutcome {
        self.submissions.fetch_add(1, Ordering::SeqCst);
        let id = statement.id();
        if !self.accepted.lock().unwrap().insert(id.0) {
            return SubmitOutcome::judged(Refusal::Repeated.code());
        }
        SubmitOutcome::Accepted
    }

    fn anchored(&self, root: &RootRead) -> bool {
        !self.hold.load(Ordering::SeqCst) && self.model.anchored(root)
    }
});
