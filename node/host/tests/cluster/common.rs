//! The cluster the tests share, and what they check of it.

use std::collections::HashMap;
use std::ops::RangeInclusive;
use std::sync::atomic::{AtomicBool, AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vos_checker::calls::{done, install_at_leader};
use vos_checker::programs::Programs;
pub use vos_checker::spaces::wait_in_process as wait_until;
use vos_checker::spaces::{HeldPort, IN_PROCESS_WAIT, open_node, space};
use vos_net::memory::{Endpoint, Hub};
use vos_net::{Arrivals, Class, Network};
use vos_node::{CallError, Config, Hooks, Node, Peers, ReplaceError, Reply, Space};
use vos_wire::batch::Request;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, Session};
use vos_wire::ingress::Unplaced;
use vos_wire::peer::{NodeNumber, PeerMessage};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode, WindowClock};

pub const COUNTER: InstanceId = InstanceId(1);
pub const ALICE: Principal = Principal::Client([1; 32]);

/// How long a node's commit may wait before its writer counts as stalled
/// and its groups hand over: every node's store shares the host's one
/// disk, whose syncs a loaded host holds for seconds at a time.
pub const WRITER_STALL: Duration = Duration::from_secs(5);

/// Past how long a follower drops a snapshot it staged in part once the
/// stream stops arriving (30 s).
pub const STAGED_IDLE: Duration = Duration::from_secs(45);

/// What a test sets in node `number`'s config, past the harness's own.
type Tuning = Box<dyn Fn(NodeNumber, &mut Config) + Send + Sync>;

/// Nodes 1..=count of one space, on a hub or over QUIC on localhost.
pub struct Cluster {
    pub hub: Hub,
    quic: bool,
    pub space: Space,
    pub programs: Arc<Programs>,
    pub dirs: Vec<tempfile::TempDir>,
    nodes: Vec<Option<Node>>,
    /// Over QUIC, each stopped node's peer port, held until it starts.
    held: Vec<Option<HeldPort>>,
    tuning: Tuning,
    /// Alice's session at each agent, for the calls the test makes, timed
    /// at the first of them: a session timed at the cluster's start, or at
    /// another agent's first call, may be stale by the
    /// time a loaded host makes its first call.
    sessions: Mutex<HashMap<AgentId, Session>>,
    /// How far each node's clock is set ahead of its own, by node, from
    /// node 1.
    pub offsets: Vec<Arc<AtomicI64>>,
}

impl Cluster {
    /// Nodes 1..=count on the hub, as the harness configures them.
    pub fn new(count: u8) -> Self {
        Self::build(
            count,
            false,
            Some(WindowClock::DEFAULT),
            Box::new(|_, _| {}),
        )
    }

    /// Nodes 1..=count on the hub, as [`Cluster::tuned`] makes them, of a
    /// space founded with `clock`, or (`None`) of no space.
    pub fn in_space(
        count: u8,
        clock: Option<WindowClock>,
        tuning: impl Fn(NodeNumber, &mut Config) + Send + Sync + 'static,
    ) -> Self {
        Self::build(count, false, clock, Box::new(tuning))
    }

    /// Nodes 1..=count on the hub, as [`Cluster::in_space`] makes them, of
    /// a space founded with `clock` by `founders` alone.
    pub fn founded_by(
        count: u8,
        founders: &[NodeNumber],
        clock: WindowClock,
        tuning: impl Fn(NodeNumber, &mut Config) + Send + Sync + 'static,
    ) -> Self {
        let founders = founders.to_vec();
        Self::build_founded(count, false, Some(clock), Box::new(tuning), |number| {
            founders.contains(&number)
        })
    }

    /// Nodes 1..=count over QUIC on localhost.
    pub fn over_quic(count: u8) -> Self {
        Self::build(count, true, Some(WindowClock::DEFAULT), Box::new(|_, _| {}))
    }

    /// Nodes 1..=count on the hub, each config tuned by `tuning` past the
    /// harness's own: elections of one to two seconds, slow enough that a
    /// host starved for a second does not let a heartbeat lapse and move a
    /// leader a test calls, a writer stalled only past [`WRITER_STALL`], a
    /// heartbeat every 10 ms, two executors, and each node's clock a few
    /// milliseconds from the others'.
    pub fn tuned(
        count: u8,
        tuning: impl Fn(NodeNumber, &mut Config) + Send + Sync + 'static,
    ) -> Self {
        Self::build(count, false, Some(WindowClock::DEFAULT), Box::new(tuning))
    }

    /// Nodes 1..=count on the hub, each with hooks of its own: the
    /// cluster, and the hooks by node.
    pub fn with_hooks<H: Hooks + Default + 'static>(count: u8) -> (Self, Vec<Arc<H>>) {
        let hooks: Vec<Arc<H>> = (0..count).map(|_| Arc::default()).collect();
        let each = hooks.clone();
        let cluster = Self::tuned(count, move |number, config| {
            config.hooks = each[usize::from(number) - 1].clone();
        });
        (cluster, hooks)
    }

    /// Nodes 1..=count on the hub, every one with `hooks`.
    pub fn hooked(count: u8, hooks: Arc<dyn Hooks>) -> Self {
        Self::tuned(count, move |_, config| config.hooks = hooks.clone())
    }

    fn build(count: u8, quic: bool, clock: Option<WindowClock>, tuning: Tuning) -> Self {
        Self::build_founded(count, quic, clock, tuning, |_| true)
    }

    fn build_founded(
        count: u8,
        quic: bool,
        clock: Option<WindowClock>,
        tuning: Tuning,
        founding: impl Fn(NodeNumber) -> bool,
    ) -> Self {
        let programs = Arc::new(Programs::load());
        let dirs: Vec<tempfile::TempDir> =
            (0..count).map(|_| tempfile::tempdir().unwrap()).collect();
        let mut space = space(&programs.agent, &dirs, |number| {
            format!("http://node-{number}")
        });
        // A space founded as `vos space up` founds it.
        if let Some(clock) = clock {
            let mut genesis = space.found(clock, 0, [7; 16]).unwrap();
            genesis.nodes.retain(|(number, _)| founding(*number));
            space = space.with_genesis(genesis).unwrap();
        }
        let mut cluster = Self {
            hub: Hub::new(7),
            quic,
            space,
            programs,
            dirs,
            nodes: (0..count).map(|_| None).collect(),
            held: (0..count).map(|_| None).collect(),
            tuning,
            sessions: Mutex::default(),
            offsets: (0..count).map(|_| Arc::default()).collect(),
        };
        for number in 1..=count {
            cluster.start(number);
        }
        cluster
    }

    fn config(&self, number: NodeNumber) -> Config {
        let mut config = Config::new(self.programs.agent.clone());
        config.executors = 2;
        config.space = Some(self.space.clone());
        config.peers = if self.quic {
            Peers::Quic
        } else {
            Peers::Hub(self.hub.clone())
        };
        config.election_timeout_ms = (1_000, 2_000);
        config.heartbeat_ms = 10;
        config.writer_stall = WRITER_STALL;
        // Each node's own clock, a few milliseconds apart, and as far
        // ahead as the test sets it.
        let skew = u64::from(number) * 7;
        let offset = Arc::clone(&self.offsets[usize::from(number) - 1]);
        config.clock = Arc::new(move || {
            (vos_node::wall_clock() + skew).saturating_add_signed(offset.load(Ordering::SeqCst))
        });
        (self.tuning)(number, &mut config);
        config
    }

    pub fn start(&mut self, number: NodeNumber) {
        let at = usize::from(number) - 1;
        let dir = self.dirs[at].path().to_path_buf();
        drop(self.held[at].take());
        let node = open_node(number, &dir, || self.config(number));
        self.nodes[at] = Some(node);
    }

    pub fn stop(&mut self, number: NodeNumber) {
        let at = usize::from(number) - 1;
        if let Some(node) = self.nodes[at].take() {
            node.shutdown();
            if self.quic {
                let node = self.space.nodes().iter().find(|node| node.number == number);
                self.held[at] = Some(HeldPort::udp(node.expect("in the space").peer));
            }
        }
    }

    pub fn node(&self, number: NodeNumber) -> &Node {
        self.nodes[usize::from(number) - 1]
            .as_ref()
            .expect("a running node")
    }

    pub fn running(&self) -> impl Iterator<Item = (NodeNumber, &Node)> {
        self.nodes
            .iter()
            .zip(1..)
            .filter_map(|(node, number)| Some((number, node.as_ref()?)))
    }

    /// The one running node leading `agent`, once there is one. Past the
    /// deadline, what each running replica says of itself.
    #[track_caller]
    pub fn leader(&self, agent: AgentId) -> NodeNumber {
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            let leading: Vec<NodeNumber> = self
                .running()
                .filter(|(_, node)| node.leads(agent))
                .map(|(number, _)| number)
                .collect();
            if let [leader] = leading[..] {
                return leader;
            }
            if Instant::now() >= until {
                let replicas: Vec<_> = self
                    .running()
                    .map(|(number, node)| (number, node.replica(agent), node.placement(agent)))
                    .collect();
                panic!("timed out: a leader; the replicas: {replicas:?}");
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    /// The node leading `agent`, an agent on nodes 1 to 3, and the first
    /// of the others.
    #[track_caller]
    pub fn leader_and_follower(&self, agent: AgentId) -> (NodeNumber, NodeNumber) {
        let leader = self.leader(agent);
        let follower = (1..=3).find(|number| *number != leader).unwrap();
        (leader, follower)
    }

    /// The counter installed at `agent`'s leader.
    pub fn install(&self, agent: AgentId) {
        self.install_package(agent, COUNTER, &self.programs.counter_elf);
    }

    /// Package `elf` installed as `instance` at `agent`'s leader, followed
    /// as leadership moves.
    pub fn install_package(&self, agent: AgentId, instance: InstanceId, elf: &[u8]) {
        install_at_leader(|| self.node(self.leader(agent)), agent, instance, elf);
    }

    /// Node `at` replaces `out` by `inn` among `agent`'s replicas,
    /// `before`: answered with the replicas after, in order, which this
    /// gives back. Refused for not leading, or unanswered, it goes again
    /// at the agent's leader, as an operator follows it: under load an
    /// election may move it mid-change. A try after one that went through
    /// finds `out` gone or `inn` placed, and waits for the change to end.
    #[track_caller]
    pub fn replace(
        &self,
        at: NodeNumber,
        agent: AgentId,
        before: &[NodeNumber],
        out: NodeNumber,
        inn: NodeNumber,
    ) -> Vec<NodeNumber> {
        let after = replaced(before, out, inn);
        let until = Instant::now() + IN_PROCESS_WAIT;
        let mut node = at;
        let mut again = false;
        loop {
            match self.node(node).replace(agent, out, inn) {
                Ok(replicas) => {
                    assert_eq!(replicas, after);
                    return after;
                }
                Err(ReplaceError::Unplaced(Unplaced::NotAReplica | Unplaced::AlreadyAReplica))
                    if again =>
                {
                    wait_until("the replacement ends", || {
                        self.node(self.leader(agent))
                            .placement(agent)
                            .is_some_and(|placement| {
                                placement.replicas == after
                                    && placement.committed
                                    && !placement.joint
                            })
                    });
                    return after;
                }
                Err(
                    ReplaceError::Call(CallError::NotLeader(_) | CallError::TimedOut)
                    | ReplaceError::TimedOut
                    | ReplaceError::Unplaced(Unplaced::InProgress),
                ) if Instant::now() < until => {
                    std::thread::sleep(Duration::from_millis(100));
                    node = self.leader(agent);
                    again = true;
                }
                other => panic!("the replacement: {other:?}"),
            }
        }
    }

    /// Node `number` has applied `agent` as far as node `ahead` had when
    /// it last looked.
    #[track_caller]
    pub fn caught_up(&self, number: NodeNumber, agent: AgentId, ahead: NodeNumber) {
        wait_until(&format!("node {number} applies as far as {ahead}"), || {
            self.node(number).applied(agent) >= self.node(ahead).applied(agent)
        });
    }

    /// An agent on `replicas`, created at the first of them, once every
    /// replica runs its group.
    pub fn agent(&self, replicas: &[NodeNumber]) -> AgentId {
        let agent = self
            .node(replicas[0])
            .create_replicated(replicas.to_vec())
            .unwrap();
        wait_until("every replica runs the group", || {
            replicas
                .iter()
                .all(|number| self.node(*number).applied(agent).is_some())
        });
        agent
    }

    /// The space's representative on `replicas`, created at node 1, the
    /// space's first founding node, with its actor installed, once every
    /// replica runs its group.
    pub fn representative(&self, replicas: &[NodeNumber]) -> AgentId {
        let agent = self
            .node(1)
            .create_representative(replicas.to_vec())
            .unwrap();
        wait_until("every replica runs the representative", || {
            replicas
                .iter()
                .all(|number| self.node(*number).applied(agent).is_some())
        });
        self.install_package(
            agent,
            vos_wire::served::REPRESENTATIVE,
            &vos_checker::programs::representative_package(),
        );
        agent
    }

    /// An agent on `replicas`, as [`Cluster::agent`] makes it, with the
    /// counter installed.
    pub fn counter_agent(&self, replicas: &[NodeNumber]) -> AgentId {
        let agent = self.agent(replicas);
        self.install(agent);
        agent
    }

    /// Alice's session at `agent`, timed when the test first asks for it,
    /// by the clock of the node leading `agent` then, as the test sets it:
    /// the clock a new session's time must be near.
    pub fn session(&self, agent: AgentId) -> Session {
        let mut sessions = self.sessions.lock().unwrap();
        *sessions.entry(agent).or_insert_with(|| Session {
            key: [1; 32],
            name: [1; 16],
            t0: self.clock(self.leader(agent)),
        })
    }

    /// Node `number`'s clock as the cluster sets it: the wall's, its few
    /// milliseconds of skew, and its offset.
    pub fn clock(&self, number: NodeNumber) -> u64 {
        let offset = self.offsets[usize::from(number) - 1].load(Ordering::SeqCst);
        (vos_node::wall_clock() + u64::from(number) * 7).saturating_add_signed(offset)
    }

    /// Alice's request adding `by` to `agent`'s counter, at `sequence` of
    /// the test's session there.
    pub fn request(&self, agent: AgentId, sequence: u64, by: u64) -> Request {
        Request {
            session: self.session(agent),
            sequence,
            caller: ALICE,
            instance: COUNTER,
            method: self.programs.method("increment"),
            arguments: by.encode(),
        }
    }

    /// Alice's request of `agent`'s counter's `method` with `arguments`,
    /// at `sequence` of the test's session there.
    pub fn request_of(
        &self,
        agent: AgentId,
        sequence: u64,
        method: MethodId,
        arguments: Vec<u8>,
    ) -> Request {
        Request {
            method,
            arguments,
            ..self.request(agent, sequence, 0)
        }
    }

    pub fn increment(
        &self,
        at: NodeNumber,
        agent: AgentId,
        sequence: u64,
        by: u64,
    ) -> Result<Reply, CallError> {
        smol::block_on(self.node(at).call(agent, self.request(agent, sequence, by)))
    }

    /// `request` at `agent`'s leader, followed when it moves: a call sent
    /// again at its sequence runs once, and is answered from the reply
    /// window when it already has, so one unanswered in time goes again
    /// too. Each retry waits twice as long as the last, from 10 ms to half
    /// a second, so an election has time to end, for as long as a test
    /// waits for the nodes to settle: a starved host may take several
    /// elections to settle one.
    pub fn call_at_leader(&self, agent: AgentId, request: Request) -> Result<Reply, CallError> {
        let until = Instant::now() + IN_PROCESS_WAIT;
        let mut backoff = Duration::from_millis(10);
        loop {
            let node = self.node(self.leader(agent));
            match smol::block_on(node.call(agent, request.clone())) {
                Err(CallError::NotLeader(_) | CallError::TimedOut) if Instant::now() < until => {
                    std::thread::sleep(backoff);
                    backoff = (backoff * 2).min(Duration::from_millis(500));
                }
                reply => return reply,
            }
        }
    }

    /// [`Cluster::increment`] at `agent`'s leader, followed as
    /// [`Cluster::call_at_leader`] follows it.
    pub fn increment_at_leader(
        &self,
        agent: AgentId,
        sequence: u64,
        by: u64,
    ) -> Result<Reply, CallError> {
        self.call_at_leader(agent, self.request(agent, sequence, by))
    }

    /// Each of `sequences` added to `agent`'s counter at node `at`, in
    /// order, each at that sequence of the session whose every earlier
    /// call added its own: each is answered with the sum of the sequences
    /// through it. That sum at the last. A call `at` refuses for not
    /// leading, or leaves unanswered in time, goes again at the agent's
    /// leader, followed as [`Cluster::call_at_leader`] does: under load an
    /// election may move it mid-sequence.
    #[track_caller]
    pub fn increments(
        &self,
        at: NodeNumber,
        agent: AgentId,
        sequences: RangeInclusive<u64>,
    ) -> u64 {
        let mut total = 0;
        for sequence in sequences {
            total = sequence * (sequence + 1) / 2;
            assert_eq!(
                done(match self.increment(at, agent, sequence, sequence) {
                    Err(CallError::NotLeader(_) | CallError::TimedOut) =>
                        self.increment_at_leader(agent, sequence, sequence),
                    reply => reply,
                }),
                total,
                "sequence {sequence}"
            );
        }
        total
    }

    pub fn value(&self, at: NodeNumber, agent: AgentId) -> u64 {
        match self.query_value(at, agent) {
            Ok(Outcome::Done(bytes)) => u64::decode(&bytes).unwrap().0,
            other => panic!("{other:?}"),
        }
    }

    pub fn query_value(&self, at: NodeNumber, agent: AgentId) -> Result<Outcome, CallError> {
        smol::block_on(self.node(at).query(
            agent,
            ALICE,
            COUNTER,
            self.programs.method("value"),
            Vec::new(),
        ))
    }

    /// Every running node the newest placement of `agent` names runs it,
    /// and each holds the same rows at the same applied index, both read
    /// from one store snapshot of its own: an applied index read apart
    /// from the rows may match while a committed entry is still applying
    /// on one replica, its rows read after it a later entry's. A replica
    /// still learning of the agent, or behind the others, is waited for;
    /// replicas at one applied index whose rows differ have diverged.
    pub fn converged(&self, agent: AgentId) {
        let mut views = Vec::new();
        wait_until("every replica applies the same", || {
            let Some(placement) = self
                .running()
                .filter_map(|(_, node)| node.placement(agent))
                .max_by_key(|placement| placement.order())
            else {
                return false;
            };
            let replicas: Vec<&Node> = self
                .running()
                .filter(|(number, _)| placement.replicas.contains(number))
                .map(|(_, node)| node)
                .collect();
            if replicas.iter().any(|node| node.applied(agent).is_none()) {
                return false;
            }
            views = replicas
                .iter()
                .map(|node| applied_rows(node, agent))
                .collect();
            views.iter().all(|(applied, _)| applied.is_some())
                && views.windows(2).all(|pair| pair[0].0 == pair[1].0)
        });
        assert!(views.len() > 1, "fewer than two replicas to compare");
        assert!(
            views.windows(2).all(|pair| pair[0].1 == pair[1].1),
            "the replicas' rows differ at applied index {:?}",
            views[0].0
        );
    }

    /// Node `number` compacts `agent`'s log past `index`.
    #[track_caller]
    pub fn compacted_past(&self, number: NodeNumber, agent: AgentId, index: u64) {
        wait_until(&format!("node {number} compacts past {index}"), || {
            log_start(self.node(number), agent) > index
        });
    }

    /// Every running node holds `replicas` as `agent`'s placement,
    /// committed and final.
    pub fn placed(&self, agent: AgentId, replicas: &[NodeNumber]) {
        wait_until("every node holds the final placement", || {
            self.running().all(|(_, node)| {
                node.placement(agent).is_some_and(|placement| {
                    placement.replicas == replicas && placement.committed && !placement.joint
                })
            })
        });
    }

    /// Node `number` stopped, and the test on the hub in its place.
    pub fn impersonate(&mut self, number: NodeNumber) -> Impersonation {
        self.stop(number);
        let (endpoint, arrivals) = self.hub.join(number);
        endpoint.set_peers(self.space.peers());
        Impersonation { endpoint, arrivals }
    }
}

/// The test speaking for a stopped node, on the hub.
pub struct Impersonation {
    endpoint: Endpoint,
    arrivals: Arrivals,
}

impl Impersonation {
    /// `message` sent to node `to` as a request, on its stream.
    pub fn send(&self, to: NodeNumber, message: &PeerMessage) {
        self.endpoint
            .send(
                to,
                Class::Requests,
                vos_node::peer::stream(message),
                message.encode(),
            )
            .unwrap();
    }

    /// The first request to arrive that `answer` takes, past the others
    /// the nodes send, within 10 s.
    pub fn answer<T>(&self, mut answer: impl FnMut(PeerMessage) -> Option<T>) -> T {
        let until = Instant::now() + Duration::from_secs(10);
        loop {
            let left = until.saturating_duration_since(Instant::now());
            let incoming = smol::block_on(async {
                async { self.arrivals.requests.recv().await.ok() }
                    .or(async {
                        smol::Timer::after(left).await;
                        None
                    })
                    .await
            })
            .expect("an answer within 10 s");
            if let Some(taken) = vos_node::peer::decode(&incoming.frame)
                .ok()
                .and_then(&mut answer)
            {
                return taken;
            }
        }
    }
}

/// Nodes that compact their logs every few entries, and send snapshots in
/// small chunks.
pub fn compacting(_: NodeNumber, config: &mut Config) {
    config.compact_every = 8;
    config.compact_tail = 2;
    config.snapshot_chunk = 64;
}

/// Withholds every blob this node is asked for, while told to.
#[derive(Default)]
pub struct WithholdBlobs(AtomicBool);

impl WithholdBlobs {
    pub fn withhold(&self, withhold: bool) {
        self.0.store(withhold, Ordering::SeqCst);
    }
}

impl Hooks for WithholdBlobs {
    fn serve_blob(&self, _: NodeNumber, _: &[u8; 32]) -> bool {
        !self.0.load(Ordering::SeqCst)
    }
}

/// An agent's rows: each key and value.
pub type Rows = Vec<(Vec<u8>, Vec<u8>)>;

/// Every row of `agent`'s applied state on `node`.
pub fn rows(node: &Node, agent: AgentId) -> Rows {
    applied_rows(node, agent).1
}

/// `agent`'s applied index on `node` and its rows, from one store
/// snapshot.
pub fn applied_rows(node: &Node, agent: AgentId) -> (Option<u64>, Rows) {
    let snapshot = node.store().snapshot();
    let applied = snapshot.applied(agent).unwrap();
    let rows = [[0x00u8], [0x01], [0x03]]
        .iter()
        .flat_map(|prefix| {
            snapshot
                .scan(agent, prefix, None)
                .map(Result::unwrap)
                .collect::<Vec<_>>()
        })
        .collect();
    (applied, rows)
}

/// Where `agent`'s log on `node` starts: the index it was compacted
/// through, or a snapshot installed at.
pub fn log_start(node: &Node, agent: AgentId) -> u64 {
    node.store().raft(agent).unwrap().log_start.0
}

/// `node` holds no epoch of `agent`'s but its current one: the one a
/// snapshot's switch left, dropped in the background, and any later stream
/// a loaded host's leader began that the follower no longer needs, dropped
/// once idle.
#[track_caller]
pub fn old_epochs_dropped(node: &Node, agent: AgentId) {
    let mut stale = Vec::new();
    let dropped = vos_checker::poll(STAGED_IDLE, || {
        stale = node.store().stale_epochs(agent).unwrap();
        stale.is_empty()
    });
    let current = node.store().snapshot().epoch(agent).unwrap();
    assert!(
        dropped,
        "the old epochs {stale:?} are left beside the current {current}, the log from {}",
        log_start(node, agent)
    );
}

/// A node no longer replicating `agent` runs no group for it and keeps
/// none of its state or log.
pub fn retired(node: &Node, agent: AgentId) {
    wait_until("the replica retires", || {
        node.applied(agent).is_none()
            && rows(node, agent).is_empty()
            && node.store().raft(agent).unwrap().log.is_empty()
    });
}

/// The hub loses `class`'s frames between nodes `a` and `b`, both ways.
pub fn cut_both(hub: &Hub, a: NodeNumber, b: NodeNumber, class: Class) {
    hub.cut_class(a, b, class);
    hub.cut_class(b, a, class);
}

/// `replicas` with `out` replaced by `inn`, in order.
pub fn replaced(replicas: &[NodeNumber], out: NodeNumber, inn: NodeNumber) -> Vec<NodeNumber> {
    let mut next: Vec<NodeNumber> = replicas
        .iter()
        .copied()
        .filter(|number| *number != out)
        .chain([inn])
        .collect();
    next.sort_unstable();
    next
}
