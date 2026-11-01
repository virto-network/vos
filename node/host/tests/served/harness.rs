//! Three nodes on a hub, each serving its API's socket, which clients
//! reach by the node's key: the cluster the served tests share, with
//! hooks that stop a leader between its apply and its answer, or hold a
//! node's refines or commits, and a clock offset per node.

use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vos_checker::hooks::Gate;
use vos_checker::programs::agent;
use vos_checker::spaces::space;
use vos_checker::{Log, Nodes};
use vos_net::memory::Hub;
use vos_node::client::Target;
use vos_node::{CallError, Config, Hooks, Node, Peers, Space};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, Session, SessionId};
use vos_wire::keys;
use vos_wire::peer::NodeNumber;
use vos_wire::records::{SessionMark, unstored};
use vos_wire::result::Outcome;
use vos_wire::{Decode, WindowClock};

pub const NODES: NodeNumber = 3;

/// Stops a leader loop once, after its commit and before its answers;
/// and holds the node's refines, or its commits, while asked.
#[derive(Default)]
pub struct Trip {
    pub armed: AtomicBool,
    pub tripped: AtomicBool,
    pub refines: Gate,
    pub commits: Gate,
}

impl Hooks for Trip {
    fn after_commit(&self, _: AgentId, _: u64) -> bool {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.tripped.store(true, Ordering::SeqCst);
            return false;
        }
        true
    }

    fn fail_refine(&self, _: AgentId, _: &vos_wire::batch::Batch) -> bool {
        self.refines.pass();
        false
    }

    fn before_commit(&self) {
        self.commits.pass();
    }
}

/// One node's slot: its node while it runs, how often it started, its hook
/// and its clock's offset.
pub struct Slot {
    node: Mutex<Option<Arc<Node>>>,
    starts: AtomicU64,
    /// Messages its earlier runs sent across nodes.
    pub sent_across: AtomicU64,
    /// Snapshots its earlier runs switched to.
    pub installed: AtomicU64,
    pub trip: Arc<Trip>,
    pub offset: Arc<AtomicI64>,
    dir: tempfile::TempDir,
}

/// [`NODES`] nodes on a hub whose losses follow its seed.
pub struct Cluster {
    pub hub: Hub,
    pub space: Space,
    agent: Vec<u8>,
    slots: Vec<Slot>,
    /// Each node, as clients reach it: its API's socket.
    targets: Vec<Target>,
    /// What happened: printed, so a run shows what it tried, and the
    /// latest events, for a failure to show what led to it.
    pub log: Log,
    /// How far every node's clock is ahead of the wall's, on top of its
    /// own offset; clients time their sessions and queries by it.
    pub offset: Arc<AtomicI64>,
    /// Clients stop at their next request while it is set.
    pub paused: AtomicBool,
    /// The venue the space anchors at, its own time the clients' (the
    /// wall's, and every node's shared offset), the space registered from
    /// window 0 when it has a genesis.
    pub venue: Arc<vos_venue::ModelVenue>,
}

impl Cluster {
    pub fn new(seed: u64) -> Self {
        Self::founded(seed, None)
    }

    /// The cluster, its space founded with `clock` when given: a clock of
    /// any length, which the model venue registers whatever it is.
    pub fn founded(seed: u64, clock: Option<WindowClock>) -> Self {
        let agent = agent();
        let dirs: Vec<tempfile::TempDir> =
            (1..=NODES).map(|_| tempfile::tempdir().unwrap()).collect();
        // The space's gateways, which its nodes name in their redirects:
        // none serves, the clients reaching each node by its key.
        let mut space = space(&agent, &dirs, |number| format!("http://node-{number}"));
        if let Some(clock) = clock {
            let mut genesis = space
                .found(WindowClock::DEFAULT, vos_node::wall_clock(), [11; 16])
                .unwrap();
            genesis.clock = clock;
            space = space.with_genesis(genesis).unwrap();
        }
        let slots: Vec<Slot> = dirs
            .into_iter()
            .map(|dir| Slot {
                node: Mutex::new(None),
                starts: AtomicU64::new(0),
                sent_across: AtomicU64::new(0),
                installed: AtomicU64::new(0),
                trip: Arc::new(Trip::default()),
                offset: Arc::new(AtomicI64::new(0)),
                dir,
            })
            .collect();
        let targets = slots
            .iter()
            .map(|slot| Target::socket(slot.dir.path().join("api.sock")))
            .collect();
        let offset = Arc::new(AtomicI64::new(0));
        let venue_offset = Arc::clone(&offset);
        let venue = Arc::new(vos_venue::ModelVenue::new(
            vos_wire::vos_anchor::VenueId([0x7e; 32]),
            Arc::new(move || {
                vos_node::wall_clock().saturating_add_signed(venue_offset.load(Ordering::SeqCst))
            }),
        ));
        if let Some(genesis) = space.genesis() {
            venue.seed(genesis, 0);
        }
        let cluster = Self {
            hub: Hub::new(seed),
            space,
            agent,
            slots,
            targets,
            log: Log::default(),
            offset,
            paused: AtomicBool::new(false),
            venue,
        };
        for number in 1..=NODES {
            cluster.start(number);
        }
        cluster
    }

    pub fn saw(&self, what: &'static str) {
        self.log.saw(what);
        if what.starts_with("fault") {
            self.log.event(format!(
                "{what}, running {:?}",
                self.slots
                    .iter()
                    .map(|slot| slot.node.lock().unwrap().is_some())
                    .collect::<Vec<_>>()
            ));
        }
    }

    pub fn slot(&self, number: NodeNumber) -> &Slot {
        &self.slots[usize::from(number) - 1]
    }

    pub fn start(&self, number: NodeNumber) {
        let slot = self.slot(number);
        let mut config = Config::new(self.agent.clone());
        config.executors = 2;
        config.hooks = slot.trip.clone();
        config.space = Some(self.space.clone());
        config.venue = Some(self.venue.clone());
        config.peers = Peers::Hub(self.hub.clone());
        // Slow enough that a host starved for a moment moves no leader a
        // test holds still; the faults move them.
        config.election_timeout_ms = (1_000, 2_000);
        // Every node's store shares the host's one disk, whose syncs a
        // loaded host holds for seconds at a time.
        config.writer_stall = Some(Duration::from_secs(5));
        config.heartbeat_ms = 10;
        // Logs compacted every few dozen entries: a node that comes back
        // catches up by a snapshot.
        config.compact_every = 64;
        config.compact_tail = 16;
        config.snapshot_chunk = 4096;
        let (offset, everyone) = (Arc::clone(&slot.offset), Arc::clone(&self.offset));
        config.clock = Arc::new(move || {
            vos_node::wall_clock().saturating_add_signed(
                everyone.load(Ordering::SeqCst) + offset.load(Ordering::SeqCst),
            )
        });
        let node = Node::open(slot.dir.path(), config).unwrap();
        node.serve_socket(&slot.dir.path().join("api.sock"), 0o600)
            .unwrap();
        slot.starts.fetch_add(1, Ordering::SeqCst);
        *slot.node.lock().unwrap() = Some(Arc::new(node));
    }

    /// Stop node `number`.
    pub fn stop(&self, number: NodeNumber) {
        let slot = self.slot(number);
        let Some(mut node) = slot.node.lock().unwrap().take() else {
            return;
        };
        // A check may hold it a moment.
        let node = loop {
            match Arc::try_unwrap(node) {
                Ok(node) => break node,
                Err(held) => {
                    node = held;
                    std::thread::sleep(Duration::from_millis(1));
                }
            }
        };
        slot.sent_across
            .fetch_add(node.messages_sent_across(), Ordering::SeqCst);
        slot.installed
            .fetch_add(node.snapshots_installed(), Ordering::SeqCst);
        node.shutdown();
    }

    /// Node `number`'s data directory, which holds its API's socket.
    #[allow(dead_code)]
    pub fn dir(&self, number: NodeNumber) -> &std::path::Path {
        self.slot(number).dir.path()
    }

    pub fn node(&self, number: NodeNumber) -> Option<Arc<Node>> {
        self.slot(number).node.lock().unwrap().clone()
    }

    /// The running node leading `agent`, if one does.
    pub fn leader(&self, agent: AgentId) -> Option<NodeNumber> {
        (1..=NODES).find(|number| self.node(*number).is_some_and(|node| node.leads(agent)))
    }

    /// The running node leading `agent`, once one does.
    #[track_caller]
    pub fn leading(&self, agent: AgentId) -> Arc<Node> {
        let mut leading = None;
        vos_checker::spaces::wait_in_process("a leader", || {
            leading = self.leader(agent).and_then(|number| self.node(number));
            leading.is_some()
        });
        leading.unwrap()
    }

    /// Each node's target by its key, for a client over the node API to
    /// follow a redirect.
    pub fn routes(&self) -> std::collections::HashMap<[u8; 32], Target> {
        self.space
            .nodes()
            .iter()
            .map(|node| (node.key, self.target(node.number).clone()))
            .collect()
    }

    /// `agent`'s identity, from the record node `at` serves.
    pub fn identity(&self, at: NodeNumber, agent: AgentId) -> [u8; 32] {
        let record = vos_node::client::agent_info(self.target(at), agent)
            .unwrap()
            .expect("the agent's record")
            .record;
        vos_node::identity(&record)
    }
}

impl Nodes for Cluster {
    fn count(&self) -> NodeNumber {
        NODES
    }

    fn target(&self, number: NodeNumber) -> &Target {
        &self.targets[usize::from(number) - 1]
    }

    fn number_at(&self, address: &str) -> Option<NodeNumber> {
        self.space
            .nodes()
            .iter()
            .find(|node| node.ingress == address)
            .map(|node| node.number)
    }

    fn offset(&self) -> i64 {
        self.offset.load(Ordering::SeqCst)
    }

    fn starts(&self, number: NodeNumber) -> u64 {
        self.slot(number).starts.load(Ordering::SeqCst)
    }

    fn leader(&self, agent: AgentId) -> Option<NodeNumber> {
        Cluster::leader(self, agent)
    }

    fn paused(&self) -> bool {
        self.paused.load(Ordering::SeqCst)
    }

    fn log(&self) -> &Log {
        &self.log
    }

    fn report(&self, agent: AgentId) -> String {
        format!(
            "agent {} applied at each node {:?}, leader {:?}\n{}",
            agent.0,
            (1..=NODES)
                .map(|number| self.node(number).map(|node| node.applied(agent)))
                .collect::<Vec<_>>(),
            Cluster::leader(self, agent),
            self.log.events(),
        )
    }

    /// The node's applied state holds what it answered, unless it
    /// restarted since.
    fn answered(
        &self,
        at: NodeNumber,
        starts: u64,
        agent: AgentId,
        session: &Session,
        sequence: u64,
    ) {
        let Some(node) = self.node(at) else {
            return;
        };
        if self.slot(at).starts.load(Ordering::SeqCst) != starts {
            return;
        }
        let mark = session_mark(&node, agent, session)
            .unwrap_or_else(|| panic!("node {at} answered before it held the session"));
        assert!(
            mark >= sequence,
            "node {at} answered sequence {sequence} at mark {mark}"
        );
    }
}

/// The last sequence of `session` that `node` applied at `agent`, if it
/// holds the session.
pub fn session_mark(node: &Node, agent: AgentId, session: &Session) -> Option<u64> {
    let snapshot = node.store().snapshot();
    let value = |key: &[u8]| {
        snapshot
            .get(agent, key)
            .unwrap()
            .map(|bytes| unstored(&bytes).expect("a stored value").to_vec())
    };
    let id = SessionId::decode(&value(&keys::session_index(session))?)
        .unwrap()
        .0;
    let mark = SessionMark::decode(&value(&keys::session(id)).expect("its mark"))
        .unwrap()
        .0;
    Some(mark.sequence)
}

/// What `node` answers a query of `instance`'s `method`, on its applied
/// state.
pub fn query(
    node: &Node,
    agent: AgentId,
    instance: InstanceId,
    method: MethodId,
) -> Result<Outcome, CallError> {
    smol::block_on(node.query(
        agent,
        Principal::Client([0; 32]),
        instance,
        method,
        Vec::new(),
    ))
}

/// A request to a down node fails at once rather than waiting out its
/// answer's deadline. Started again, the node serves on its socket.
#[test]
fn a_down_node_fails_a_request_at_once_and_serves_again() {
    let cluster = Cluster::new(1);
    cluster.stop(3);
    let asked = Instant::now();
    assert!(vos_node::client::node_id(cluster.target(3)).is_err());
    assert!(
        asked.elapsed() < Duration::from_secs(5),
        "{:?}",
        asked.elapsed()
    );
    cluster.start(3);
    vos_node::client::node_id(cluster.target(3)).unwrap();
}
