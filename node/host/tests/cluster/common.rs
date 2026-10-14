//! The cluster the tests share, and what they check of it.

use std::ops::RangeInclusive;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vos_checker::calls::done;
use vos_checker::programs::Programs;
use vos_checker::spaces::{IN_PROCESS_WAIT, open_node, space};
use vos_net::memory::{Endpoint, Hub};
use vos_net::{Arrivals, Class, Network};
use vos_node::{CallError, Config, Hooks, Node, Peers, Reply, Space};
use vos_wire::batch::{Batch, Request};
use vos_wire::ids::{AgentId, InstanceId, Principal, Session};
use vos_wire::peer::{NodeNumber, PeerMessage};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};

pub const COUNTER: InstanceId = InstanceId(1);
pub const ALICE: Principal = Principal::Client([1; 32]);

#[track_caller]
pub fn wait_until(what: &str, done: impl FnMut() -> bool) {
    vos_checker::wait_until(what, IN_PROCESS_WAIT, done);
}

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
    tuning: Tuning,
    /// Alice's session, for the calls the test makes.
    pub session: Session,
}

impl Cluster {
    /// Nodes 1..=count on the hub, as the harness configures them.
    pub fn new(count: u8) -> Self {
        Self::build(count, false, Box::new(|_, _| {}))
    }

    /// Nodes 1..=count over QUIC on localhost.
    pub fn over_quic(count: u8) -> Self {
        Self::build(count, true, Box::new(|_, _| {}))
    }

    /// Nodes 1..=count on the hub, each config tuned by `tuning` past the
    /// harness's own: elections of 40–80 ms, a heartbeat every 10 ms, two
    /// executors, and each node's clock a few milliseconds from the
    /// others'.
    pub fn tuned(
        count: u8,
        tuning: impl Fn(NodeNumber, &mut Config) + Send + Sync + 'static,
    ) -> Self {
        Self::build(count, false, Box::new(tuning))
    }

    fn build(count: u8, quic: bool, tuning: Tuning) -> Self {
        let programs = Arc::new(Programs::load());
        let dirs: Vec<tempfile::TempDir> =
            (0..count).map(|_| tempfile::tempdir().unwrap()).collect();
        let space = space(&programs.agent, &dirs, |number| {
            format!("http://node-{number}")
        });
        let mut cluster = Self {
            hub: Hub::new(7),
            quic,
            space,
            programs,
            dirs,
            nodes: (0..count).map(|_| None).collect(),
            tuning,
            session: Session {
                key: [1; 32],
                name: [1; 16],
                t0: vos_node::wall_clock(),
            },
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
        config.election_timeout_ms = (40, 80);
        config.heartbeat_ms = 10;
        // Each node's own clock, a few milliseconds apart.
        let skew = u64::from(number) * 7;
        config.clock = Arc::new(move || vos_node::wall_clock() + skew);
        (self.tuning)(number, &mut config);
        config
    }

    pub fn start(&mut self, number: NodeNumber) {
        let dir = self.dirs[usize::from(number) - 1].path().to_path_buf();
        let node = open_node(number, &dir, || self.config(number));
        self.nodes[usize::from(number) - 1] = Some(node);
    }

    pub fn stop(&mut self, number: NodeNumber) {
        if let Some(node) = self.nodes[usize::from(number) - 1].take() {
            node.shutdown();
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
        let leader = self.node(self.leader(agent));
        let installed =
            smol::block_on(leader.install(agent, COUNTER, &self.programs.counter, &[], vec![]));
        assert!(
            matches!(installed, Ok(Reply::Ran(Outcome::Done(_)))),
            "{installed:?}"
        );
    }

    /// An agent on `replicas`, created at the first of them, with the
    /// counter installed once every replica runs its group.
    pub fn counter_agent(&self, replicas: &[NodeNumber]) -> AgentId {
        let agent = self
            .node(replicas[0])
            .create_replicated(replicas.to_vec())
            .unwrap();
        wait_until("every replica runs the group", || {
            replicas
                .iter()
                .all(|number| self.node(*number).applied(agent).is_some())
        });
        self.install(agent);
        agent
    }

    /// Alice's request adding `by` to the counter, at `sequence` of the
    /// test's session.
    pub fn request(&self, sequence: u64, by: u64) -> Request {
        Request {
            session: self.session,
            sequence,
            caller: ALICE,
            instance: COUNTER,
            method: self.programs.method("increment"),
            arguments: by.encode(),
        }
    }

    pub fn increment(
        &self,
        at: NodeNumber,
        agent: AgentId,
        sequence: u64,
        by: u64,
    ) -> Result<Reply, CallError> {
        smol::block_on(self.node(at).call(agent, self.request(sequence, by)))
    }

    /// Each of `sequences` added to `agent`'s counter at node `at`, in
    /// order, each at that sequence of the session whose every earlier
    /// call added its own: each is answered with the sum of the sequences
    /// through it. That sum at the last.
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
                done(self.increment(at, agent, sequence, sequence)),
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
    /// has applied as far as the others, and holds the same rows. A
    /// replica still learning of the agent is waited for, not skipped.
    pub fn converged(&self, agent: AgentId) {
        let mut replicas = Vec::new();
        wait_until("every replica applies the same", || {
            let Some(placement) = self
                .running()
                .filter_map(|(_, node)| node.placement(agent))
                .max_by_key(|placement| placement.order())
            else {
                return false;
            };
            replicas = self
                .running()
                .filter(|(number, _)| placement.replicas.contains(number))
                .map(|(number, _)| number)
                .collect();
            let applied: Vec<Option<u64>> = replicas
                .iter()
                .map(|number| self.node(*number).applied(agent))
                .collect();
            applied.iter().all(Option::is_some) && applied.windows(2).all(|pair| pair[0] == pair[1])
        });
        let rows: Vec<Vec<(Vec<u8>, Vec<u8>)>> = replicas
            .iter()
            .map(|number| rows(self.node(*number), agent))
            .collect();
        assert!(rows.len() > 1, "fewer than two replicas to compare");
        assert!(
            rows.windows(2).all(|pair| pair[0] == pair[1]),
            "the replicas' rows differ"
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

/// Holds every refine while armed, counting those it held.
#[derive(Default)]
pub struct HoldRefines {
    armed: AtomicBool,
    held: AtomicUsize,
}

impl HoldRefines {
    pub fn arm(&self) {
        self.armed.store(true, Ordering::SeqCst);
    }

    pub fn release(&self) {
        self.armed.store(false, Ordering::SeqCst);
    }

    /// How many refines it held.
    pub fn held(&self) -> usize {
        self.held.load(Ordering::SeqCst)
    }
}

impl Hooks for HoldRefines {
    fn fail_refine(&self, _: AgentId, _: &Batch) -> bool {
        if self.armed.load(Ordering::SeqCst) {
            self.held.fetch_add(1, Ordering::SeqCst);
            while self.armed.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
        false
    }
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

/// Every row of `agent`'s applied state on `node`.
pub fn rows(node: &Node, agent: AgentId) -> Vec<(Vec<u8>, Vec<u8>)> {
    let snapshot = node.store().snapshot();
    [[0x00u8], [0x01]]
        .iter()
        .flat_map(|prefix| {
            snapshot
                .scan(agent, prefix, None)
                .map(Result::unwrap)
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Where `agent`'s log on `node` starts: the index it was compacted
/// through, or a snapshot installed at.
pub fn log_start(node: &Node, agent: AgentId) -> u64 {
    node.store().raft(agent).unwrap().log_start.0
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
