//! Replicated agents on nodes in one process, joined through a hub, each
//! with its own clock: creation and the directory, calls at the leader
//! applied on every replica alike, leader changes, a partitioned follower
//! catching up, and restarts.

use std::sync::Arc;
use std::time::{Duration, Instant};

use vos_net::memory::Hub;
use vos_node::store::{EntryKind, Store, View};
use vos_node::{CallError, Config, Hooks, Node, Peers, Reply, Space, SpaceNode};
use vos_wire::abi::refusal;
use vos_wire::batch::{Batch, Input, Message, Request};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, Session};
use vos_wire::ingress::{Contact, NodeId};
use vos_wire::keys;
use vos_wire::peer::{NodeNumber, PeerMessage};
use vos_wire::result::Outcome;
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode};

const COUNTER: InstanceId = InstanceId(1);
const ALICE: Principal = Principal::Client([1; 32]);

fn elf(path: &str) -> Vec<u8> {
    let path = format!("{}/../../agent/{path}", env!("CARGO_MANIFEST_DIR"));
    let elf = std::fs::read(&path).unwrap_or_else(|error| {
        panic!("{path}: {error}; run `just build-agent build-test-actors`")
    });
    vos_pvm_compiler::link_elf_spi(&elf).expect("links")
}

struct Programs {
    agent: Vec<u8>,
    counter: Vec<u8>,
}

impl Programs {
    fn load() -> Self {
        Self {
            agent: elf("default/target/riscv64em-vos/release/vos-agent.elf"),
            counter: elf("test-actors/target/riscv64em-vos/release/counter.elf"),
        }
    }

    fn method(&self, name: &str) -> MethodId {
        let parsed = vos_pvm::spi::parse_standard_program(&self.counter).unwrap();
        Schema::read(&parsed.ro_data)
            .unwrap()
            .methods
            .iter()
            .find(|method| method.name == name.as_bytes())
            .unwrap_or_else(|| panic!("no method {name}"))
            .id
    }
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(20);
    while !done() {
        assert!(Instant::now() < until, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// Nodes 1..=count of one space, on a hub or over QUIC on localhost.
struct Cluster {
    hub: Hub,
    quic: bool,
    space: Space,
    programs: Arc<Programs>,
    dirs: Vec<tempfile::TempDir>,
    nodes: Vec<Option<Node>>,
    hooks: Arc<dyn Hooks>,
    /// Each node's own hooks, by number, when not the shared ones.
    node_hooks: Vec<Arc<dyn Hooks>>,
    /// The agent program each node runs, by number, when not the default.
    agent_programs: Vec<Option<Vec<u8>>>,
    /// Alice's session, for the calls the test makes.
    session: Session,
}

impl Cluster {
    fn new(count: u8) -> Self {
        Self::with(count, Arc::new(vos_node::NoHooks), Vec::new())
    }

    fn over_quic(count: u8) -> Self {
        Self::build(count, Arc::new(vos_node::NoHooks), Vec::new(), true)
    }

    fn with(count: u8, hooks: Arc<dyn Hooks>, agent_programs: Vec<Option<Vec<u8>>>) -> Self {
        Self::build(count, hooks, agent_programs, false)
    }

    /// Nodes each with hooks of their own.
    fn with_node_hooks(node_hooks: Vec<Arc<dyn Hooks>>) -> Self {
        let count = node_hooks.len() as u8;
        let mut cluster = Self::build(0, Arc::new(vos_node::NoHooks), Vec::new(), false);
        cluster.node_hooks = node_hooks;
        cluster.grow(count);
        cluster
    }

    fn build(
        count: u8,
        hooks: Arc<dyn Hooks>,
        agent_programs: Vec<Option<Vec<u8>>>,
        quic: bool,
    ) -> Self {
        let mut cluster = Self {
            hub: Hub::new(7),
            quic,
            space: Space::new(Vec::new()).unwrap(),
            programs: Arc::new(Programs::load()),
            dirs: Vec::new(),
            nodes: Vec::new(),
            hooks,
            node_hooks: Vec::new(),
            agent_programs,
            session: Session {
                key: [1; 32],
                name: [1; 16],
                t0: vos_node::wall_clock(),
            },
        };
        cluster.grow(count);
        cluster
    }

    /// Make and start nodes 1..=count.
    fn grow(&mut self, count: u8) {
        let programs = Arc::clone(&self.programs);
        // A first open makes each node's key.
        let dirs: Vec<tempfile::TempDir> =
            (0..count).map(|_| tempfile::tempdir().unwrap()).collect();
        let nodes: Vec<SpaceNode> = dirs
            .iter()
            .zip(1..)
            .map(|(dir, number)| {
                let node = Node::open(dir.path(), Config::new(programs.agent.clone())).unwrap();
                let key = node.id().0;
                node.shutdown();
                // A free port, for QUIC.
                let peer = std::net::UdpSocket::bind("127.0.0.1:0")
                    .unwrap()
                    .local_addr()
                    .unwrap();
                SpaceNode {
                    number,
                    key,
                    peer,
                    ingress: format!("http://node-{number}"),
                }
            })
            .collect();
        self.space = Space::new(nodes).unwrap();
        self.dirs = dirs;
        self.nodes = (0..count).map(|_| None).collect();
        for number in 1..=count {
            self.start(number);
        }
    }

    fn config(&self, number: NodeNumber) -> Config {
        let agent = self
            .agent_programs
            .get(usize::from(number) - 1)
            .cloned()
            .flatten()
            .unwrap_or_else(|| self.programs.agent.clone());
        let mut config = Config::new(agent);
        config.executors = 2;
        config.hooks = self
            .node_hooks
            .get(usize::from(number) - 1)
            .map_or_else(|| Arc::clone(&self.hooks), Arc::clone);
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
        config
    }

    fn start(&mut self, number: NodeNumber) {
        let dir = self.dirs[usize::from(number) - 1].path().to_path_buf();
        // A restarted node binds its peer address again once the last run
        // has let it go.
        let until = Instant::now() + Duration::from_secs(5);
        let node = loop {
            match Node::open(&dir, self.config(number)) {
                Ok(node) => break node,
                Err(vos_node::Error::Data(error))
                    if Instant::now() < until && error.contains("in use") =>
                {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("node {number}: {error:?}"),
            }
        };
        self.nodes[usize::from(number) - 1] = Some(node);
    }

    fn stop(&mut self, number: NodeNumber) {
        if let Some(node) = self.nodes[usize::from(number) - 1].take() {
            node.shutdown();
        }
    }

    fn node(&self, number: NodeNumber) -> &Node {
        self.nodes[usize::from(number) - 1]
            .as_ref()
            .expect("a running node")
    }

    fn running(&self) -> impl Iterator<Item = (NodeNumber, &Node)> {
        self.nodes
            .iter()
            .zip(1..)
            .filter_map(|(node, number)| Some((number, node.as_ref()?)))
    }

    /// The one running node leading `agent`, once there is one.
    fn leader(&self, agent: AgentId) -> NodeNumber {
        let mut leader = None;
        wait_until("a leader", || {
            let leading: Vec<NodeNumber> = self
                .running()
                .filter(|(_, node)| node.leads(agent))
                .map(|(number, _)| number)
                .collect();
            leader = (leading.len() == 1).then(|| leading[0]);
            leader.is_some()
        });
        leader.unwrap()
    }

    fn install(&self, agent: AgentId) {
        let leader = self.node(self.leader(agent));
        let installed =
            smol::block_on(leader.install(agent, COUNTER, &self.programs.counter, &[], vec![]));
        assert!(
            matches!(installed, Ok(Reply::Ran(Outcome::Done(_)))),
            "{installed:?}"
        );
    }

    fn increment(
        &self,
        at: NodeNumber,
        agent: AgentId,
        sequence: u64,
        by: u64,
    ) -> Result<Reply, CallError> {
        let request = Request {
            session: self.session,
            sequence,
            caller: ALICE,
            instance: COUNTER,
            method: self.programs.method("increment"),
            arguments: by.encode(),
        };
        smol::block_on(self.node(at).call(agent, request))
    }

    fn value(&self, at: NodeNumber, agent: AgentId) -> u64 {
        let outcome = smol::block_on(self.node(at).query(
            agent,
            ALICE,
            COUNTER,
            self.programs.method("value"),
            Vec::new(),
        ))
        .unwrap();
        match outcome {
            Outcome::Done(bytes) => u64::decode(&bytes).unwrap().0,
            other => panic!("{other:?}"),
        }
    }

    /// Every running replica of `agent` has applied as far as the others,
    /// and holds the same rows.
    fn converged(&self, agent: AgentId) {
        wait_until("every replica applies the same", || {
            let applied: Vec<Option<u64>> = self
                .running()
                .filter_map(|(_, node)| node.applied(agent).map(Some))
                .collect();
            applied.windows(2).all(|pair| pair[0] == pair[1])
        });
        let rows: Vec<Vec<(Vec<u8>, Vec<u8>)>> = self
            .running()
            .filter(|(_, node)| node.applied(agent).is_some())
            .map(|(_, node)| rows(node, agent))
            .collect();
        assert!(rows.len() > 1, "fewer than two replicas to compare");
        assert!(
            rows.windows(2).all(|pair| pair[0] == pair[1]),
            "the replicas' rows differ"
        );
    }
}

/// Every row of `agent`'s applied state on `node`.
fn rows(node: &Node, agent: AgentId) -> Vec<(Vec<u8>, Vec<u8>)> {
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

fn done(reply: Result<Reply, CallError>) -> u64 {
    match reply {
        Ok(Reply::Ran(Outcome::Done(bytes))) => u64::decode(&bytes).unwrap().0,
        other => panic!("not done: {other:?}"),
    }
}

#[test]
fn an_agent_created_on_three_nodes_applies_alike_on_each() {
    let cluster = Cluster::new(3);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    assert_eq!(agent.0 >> 24, 1, "an id from the creating node's range");
    wait_until("every replica runs the group", || {
        (1..=3).all(|number| cluster.node(number).applied(agent).is_some())
    });
    cluster.install(agent);
    let leader = cluster.leader(agent);
    for (sequence, by) in [(1u64, 5u64), (2, 7), (3, 1)] {
        assert_eq!(
            done(cluster.increment(leader, agent, sequence, by)),
            [5, 12, 13][sequence as usize - 1]
        );
    }
    cluster.converged(agent);
    for number in 1..=3 {
        assert_eq!(
            cluster.value(number, agent),
            13,
            "node {number} reads its replica"
        );
    }
    let pins: Vec<Vec<[u8; 32]>> = (1..=3)
        .map(|number| cluster.node(number).pinned())
        .collect();
    assert!(!pins[0].is_empty(), "the program is pinned");
    assert!(
        pins.windows(2).all(|pair| pair[0] == pair[1]),
        "pins differ"
    );
}

#[test]
fn followers_and_other_nodes_send_callers_where_the_agent_is_served() {
    let cluster = Cluster::new(4);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    let follower = (1..=3).find(|number| *number != leader).unwrap();
    let contact = |number: NodeNumber| Contact {
        address: format!("http://node-{number}"),
        node: NodeId(cluster.space.node(number).unwrap().key),
    };
    assert_eq!(
        cluster.increment(follower, agent, 1, 1),
        Err(CallError::NotLeader(Some(contact(leader))))
    );
    wait_until("node 4 learns of the agent", || {
        matches!(
            cluster.increment(4, agent, 1, 1),
            Err(CallError::Elsewhere(_))
        )
    });
    assert_eq!(
        cluster.increment(4, agent, 1, 1),
        Err(CallError::Elsewhere((1..=3).map(contact).collect()))
    );
}

#[test]
fn a_new_leader_serves_after_the_old_one_stops_and_the_old_one_catches_up() {
    let mut cluster = Cluster::new(3);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let first = cluster.leader(agent);
    assert_eq!(done(cluster.increment(first, agent, 1, 5)), 5);
    let time = |node: &Node| {
        node.store()
            .snapshot()
            .last_result(agent)
            .unwrap()
            .unwrap()
            .0
    };
    let before = time(cluster.node(first));
    cluster.stop(first);
    let second = cluster.leader(agent);
    assert_ne!(second, first);
    // The same session goes on at the new leader.
    assert_eq!(done(cluster.increment(second, agent, 2, 7)), 12);
    assert!(time(cluster.node(second)) >= before, "batch time went back");
    cluster.start(first);
    cluster.converged(agent);
    assert_eq!(cluster.value(first, agent), 12);
}

#[test]
fn a_partitioned_follower_catches_up_and_runs_the_program_it_missed() {
    let cluster = Cluster::new(3);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    let leader = cluster.leader(agent);
    let follower = (1..=3).find(|number| *number != leader).unwrap();
    wait_until("the follower runs the group", || {
        cluster.node(follower).applied(agent).is_some()
    });
    cluster.hub.isolate(follower);
    cluster.install(agent);
    assert_eq!(done(cluster.increment(leader, agent, 1, 3)), 3);
    assert!(cluster.node(follower).pinned().is_empty());
    cluster.hub.heal();
    cluster.converged(agent);
    assert_eq!(
        cluster.node(follower).pinned(),
        cluster.node(leader).pinned()
    );
    assert_eq!(cluster.value(follower, agent), 3);
}

#[test]
fn a_restarted_follower_recovers_its_group() {
    let mut cluster = Cluster::new(3);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    let follower = (1..=3).find(|number| *number != leader).unwrap();
    assert_eq!(done(cluster.increment(leader, agent, 1, 2)), 2);
    cluster.converged(agent);
    cluster.stop(follower);
    assert_eq!(done(cluster.increment(leader, agent, 2, 3)), 5);
    cluster.start(follower);
    cluster.converged(agent);
    assert_eq!(cluster.value(follower, agent), 5);
}

#[test]
fn a_record_reaches_a_node_that_was_down_once_its_creator_restarts() {
    let mut cluster = Cluster::new(3);
    cluster.stop(3);
    // Nodes 1 and 2 are a majority: the creation is answered.
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.stop(1);
    cluster.start(3);
    std::thread::sleep(Duration::from_millis(300));
    assert!(
        cluster.node(3).applied(agent).is_none(),
        "only the creator sends it"
    );
    cluster.start(1);
    wait_until("node 3 learns of the agent", || {
        cluster.node(3).applied(agent).is_some()
    });
    cluster.install(agent);
    cluster.converged(agent);
}

#[test]
fn a_replica_with_another_agent_program_refuses_the_group() {
    let programs = Programs::load();
    // Node 3 runs another program as its agent program.
    let cluster = Cluster::with(
        3,
        Arc::new(vos_node::NoHooks),
        vec![None, None, Some(programs.counter.clone())],
    );
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    assert_ne!(leader, 3);
    assert_eq!(done(cluster.increment(leader, agent, 1, 4)), 4);
    assert!(
        cluster.node(3).applied(agent).is_none(),
        "node 3 runs no group"
    );
}

/// Fails the leader's dry run of a batch holding the poisoned argument.
struct PoisonDryRun(Vec<u8>);

impl Hooks for PoisonDryRun {
    fn fail_dry_run(&self, _: AgentId, batch: &Batch) -> bool {
        batch.inputs.iter().any(|input| match input {
            Input::Request(request) => request.arguments == self.0,
            _ => false,
        })
    }
}

#[test]
fn an_input_whose_accumulate_fails_is_isolated_before_the_log() {
    let cluster = Cluster::with(3, Arc::new(PoisonDryRun(666u64.encode())), Vec::new());
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    let node = cluster.node(leader);
    let request = |sequence: u64, by: u64| Request {
        session: cluster.session,
        sequence,
        caller: ALICE,
        instance: COUNTER,
        method: cluster.programs.method("increment"),
        arguments: by.encode(),
    };
    // Queued together, they share a batch until it fails.
    let calls: Vec<_> = [(1u64, 1u64), (2, 666), (3, 2)]
        .into_iter()
        .map(|(sequence, by)| node.call(agent, request(sequence, by)))
        .collect();
    let replies: Vec<_> = calls.into_iter().map(smol::block_on).collect();
    assert_eq!(done(replies[0].clone()), 1);
    assert_eq!(replies[1], Ok(Reply::Failed));
    assert_eq!(replies[2], Ok(Reply::Refused(refusal::SEQUENCE)));
    cluster.converged(agent);
    // No entry carries the poisoned input.
    let store = node.store();
    let applied = node.applied(agent).unwrap();
    for index in 1..=applied {
        let entry = store.log_entry(agent, index).unwrap().unwrap();
        if entry.kind == EntryKind::Result {
            let poisoned = 666u64.encode();
            assert!(
                !entry
                    .body
                    .windows(poisoned.len())
                    .any(|window| window == poisoned),
                "entry {index} carries the poisoned input"
            );
        }
    }
}

#[test]
fn a_record_reaches_a_node_that_comes_up_later_while_its_creator_runs() {
    let mut cluster = Cluster::new(3);
    cluster.stop(3);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    std::thread::sleep(Duration::from_millis(100));
    cluster.start(3);
    wait_until("the creator's resends reach node 3", || {
        cluster.node(3).applied(agent).is_some()
    });
}

#[test]
fn three_nodes_over_quic_replicate_and_fail_over() {
    let mut cluster = Cluster::over_quic(3);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let first = cluster.leader(agent);
    assert_eq!(done(cluster.increment(first, agent, 1, 5)), 5);
    cluster.converged(agent);
    cluster.stop(first);
    let second = cluster.leader(agent);
    assert_eq!(done(cluster.increment(second, agent, 2, 6)), 11);
    cluster.start(first);
    cluster.converged(agent);
    assert_eq!(cluster.value(first, agent), 11);
}

/// Fails the apply of the first entry of each agent whose result carries
/// the marked bytes, on every replica alike (they apply the same entries).
struct FailFirstApply {
    mark: Vec<u8>,
    first: std::sync::Mutex<std::collections::HashMap<AgentId, u64>>,
}

impl Hooks for FailFirstApply {
    fn fail_apply(&self, agent: AgentId, index: u64, result: &[u8]) -> bool {
        if !result
            .windows(self.mark.len())
            .any(|window| window == self.mark)
        {
            return false;
        }
        let mut first = self.first.lock().unwrap();
        *first.entry(agent).or_insert(index) == index
    }
}

#[test]
fn a_result_that_applies_as_no_writes_is_retried_not_answered() {
    let by = 0x0102_0304_0506_0708u64;
    let hooks = Arc::new(FailFirstApply {
        mark: by.encode(),
        first: Default::default(),
    });
    let cluster = Cluster::with(3, hooks.clone(), Vec::new());
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    // The first entry carrying it applies as no writes everywhere; the
    // leader runs its inputs again rather than answer them.
    assert_eq!(done(cluster.increment(leader, agent, 1, by)), by);
    assert!(
        hooks.first.lock().unwrap().contains_key(&agent),
        "an apply failed"
    );
    cluster.converged(agent);
    for number in 1..=3 {
        assert_eq!(
            cluster.value(number, agent),
            by,
            "applied once, on node {number}"
        );
    }
}

/// Withholds every blob this node is asked for, once armed.
#[derive(Default)]
struct WithholdBlobs(std::sync::atomic::AtomicBool);

impl Hooks for WithholdBlobs {
    fn serve_blob(&self) -> bool {
        !self.0.load(std::sync::atomic::Ordering::SeqCst)
    }
}

#[test]
fn a_follower_fetches_a_blob_from_another_member_when_the_leader_withholds_it() {
    let hooks: Vec<Arc<WithholdBlobs>> = (0..3).map(|_| Arc::default()).collect();
    let cluster = Cluster::with_node_hooks(
        hooks
            .iter()
            .map(|hooks| Arc::clone(hooks) as Arc<dyn Hooks>)
            .collect(),
    );
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    let leader = cluster.leader(agent);
    let follower = (1..=3).find(|number| *number != leader).unwrap();
    wait_until("the follower runs the group", || {
        cluster.node(follower).applied(agent).is_some()
    });
    cluster.hub.isolate(follower);
    cluster.install(agent);
    assert_eq!(done(cluster.increment(leader, agent, 1, 3)), 3);
    // The leader no longer serves blobs: the follower must ask the other.
    hooks[usize::from(leader) - 1]
        .0
        .store(true, std::sync::atomic::Ordering::SeqCst);
    cluster.hub.heal();
    cluster.converged(agent);
    assert_eq!(
        cluster.node(follower).pinned(),
        cluster.node(leader).pinned()
    );
    assert_eq!(cluster.value(follower, agent), 3);
}

impl Cluster {
    /// `from`'s forward of `by` to `to`'s counter, called at node `at`.
    fn forward(
        &self,
        at: NodeNumber,
        from: AgentId,
        sequence: u64,
        to: AgentId,
        by: u64,
    ) -> Result<Reply, CallError> {
        let request = Request {
            session: self.session,
            sequence,
            caller: ALICE,
            instance: COUNTER,
            method: self.programs.method("forward"),
            arguments: (to.0, COUNTER.0, by).encode(),
        };
        smol::block_on(self.node(at).call(from, request))
    }

    /// Forward `by` from `from` to `to`, at whichever node leads `from`,
    /// until it is answered.
    fn forward_once(&self, from: AgentId, sequence: u64, to: AgentId, by: u64) {
        wait_until("a forward is answered", || {
            let leader = self.leader(from);
            matches!(
                self.forward(leader, from, sequence, to, by),
                Ok(Reply::Ran(Outcome::Done(_)))
            )
        });
    }

    /// The entries `agent`'s outbox holds at node `at`.
    fn outbox(&self, at: NodeNumber, agent: AgentId) -> usize {
        self.node(at)
            .store()
            .snapshot()
            .scan(agent, &keys::outbox_prefix(), None)
            .count()
    }

    /// `to`'s counter is `total` at every running replica in `replicas`,
    /// and `from`'s outbox is empty at every running replica of it.
    fn delivered(&self, from: (AgentId, &[NodeNumber]), to: (AgentId, &[NodeNumber]), total: u64) {
        wait_until("every message is applied once and acknowledged", || {
            to.1.iter()
                .filter(|number| self.nodes[usize::from(**number) - 1].is_some())
                .all(|number| self.value(*number, to.0) == total)
                && from
                    .1
                    .iter()
                    .filter(|number| self.nodes[usize::from(**number) - 1].is_some())
                    .all(|number| self.outbox(*number, from.0) == 0)
        });
    }

    fn agent_on(&self, replicas: Vec<NodeNumber>) -> AgentId {
        let agent = self.node(replicas[0]).create_replicated(replicas).unwrap();
        self.install(agent);
        agent
    }
}

/// A message to an agent on nodes the sender's node does not replicate
/// goes through the directory to one of them, which relays it to its
/// leader; it applies once, and its acknowledgement comes back.
#[test]
fn a_message_reaches_an_agent_on_other_nodes_once() {
    let cluster = Cluster::new(3);
    let sender = cluster.agent_on(vec![1]);
    let target = cluster.agent_on(vec![2, 3]);
    for (sequence, by) in [(1, 5), (2, 7)] {
        cluster.forward_once(sender, sequence, target, by);
    }
    cluster.delivered((sender, &[1]), (target, &[2, 3]), 12);
    assert!(cluster.node(1).messages_sent_across() > 0);
}

/// With the sender on {1, 2, 3} and the target on {2, 3, 4}, a message
/// goes to the target's leader from a replica of both, or through the
/// directory and a relay from node 1.
#[test]
fn messages_cross_overlapping_replica_sets() {
    let cluster = Cluster::new(4);
    let sender = cluster.agent_on(vec![1, 2, 3]);
    let target = cluster.agent_on(vec![2, 3, 4]);
    let mut total = 0;
    for sequence in 1..=6 {
        cluster.forward_once(sender, sequence, target, sequence);
        total += sequence;
    }
    cluster.delivered((sender, &[1, 2, 3]), (target, &[2, 3, 4]), total);
}

/// The target's leader stops with messages in flight: the sender's
/// rounds deliver them to the next, once.
#[test]
fn a_receivers_leader_stopping_loses_no_message() {
    let mut cluster = Cluster::new(3);
    let sender = cluster.agent_on(vec![1]);
    let target = cluster.agent_on(vec![2, 3]);
    for sequence in 1..=4 {
        cluster.forward_once(sender, sequence, target, 10);
    }
    let leader = cluster.leader(target);
    cluster.stop(leader);
    for sequence in 5..=8 {
        cluster.forward_once(sender, sequence, target, 10);
    }
    cluster.start(leader);
    cluster.delivered((sender, &[1]), (target, &[2, 3]), 80);
}

/// The sender's leader stops with its outbox unacknowledged: the next
/// leader delivers what it holds, once.
#[test]
fn a_senders_leader_stopping_loses_no_message() {
    let mut cluster = Cluster::new(4);
    let sender = cluster.agent_on(vec![1, 2, 3]);
    let target = cluster.agent_on(vec![4]);
    // The target is down: the messages wait in the sender's outbox.
    cluster.stop(4);
    for sequence in 1..=3 {
        cluster.forward_once(sender, sequence, target, 3);
    }
    let leader = cluster.leader(sender);
    cluster.stop(leader);
    cluster.start(4);
    cluster.leader(sender);
    cluster.start(leader);
    cluster.delivered((sender, &[1, 2, 3]), (target, &[4]), 9);
}

/// A backlog larger than a window drains, driven by acknowledgements.
#[test]
fn a_backlog_beyond_a_window_drains() {
    let mut cluster = Cluster::new(3);
    let sender = cluster.agent_on(vec![1]);
    let target = cluster.agent_on(vec![2, 3]);
    cluster.stop(2);
    cluster.stop(3);
    for sequence in 1..=300 {
        cluster.forward_once(sender, sequence, target, 1);
    }
    cluster.start(2);
    cluster.start(3);
    let until = Instant::now() + Duration::from_secs(60);
    while cluster.value(2, target) < 300 {
        assert!(Instant::now() < until, "the backlog did not drain");
        std::thread::sleep(Duration::from_millis(20));
    }
    cluster.delivered((sender, &[1]), (target, &[2, 3]), 300);
}

/// A message's hop is checked: one from a node that replicates neither
/// the sender nor the target is dropped.
#[test]
fn a_message_from_a_node_replicating_neither_end_is_dropped() {
    let mut cluster = Cluster::new(4);
    let sender = cluster.agent_on(vec![1, 2, 3]);
    let target = cluster.agent_on(vec![1, 2, 3]);
    cluster.stop(4);
    let (forger, _arrivals) = cluster.hub.join(4);
    vos_net::Network::set_peers(&forger, cluster.space.peers());
    let leader = cluster.leader(target);
    for relayed in [false, true] {
        let message = PeerMessage::Deliver {
            to: target,
            message: Message {
                from: sender,
                sequence: 1,
                instance: COUNTER,
                method: cluster.programs.method("increment"),
                arguments: 9u64.encode(),
            },
            relayed,
        };
        vos_net::Network::send(
            &forger,
            leader,
            vos_net::Class::Requests,
            u64::from(target.0),
            message.encode(),
        )
        .unwrap();
    }
    std::thread::sleep(Duration::from_millis(300));
    assert_eq!(cluster.value(leader, target), 0, "a forged message ran");
}

/// A replica that does not lead relays a message to its leader: node 1's
/// first window goes through the target's replica its turn picks, node 3,
/// made a follower here.
#[test]
fn a_follower_relays_a_message_to_its_leader() {
    let mut cluster = Cluster::new(4);
    let sender = cluster.agent_on(vec![1]);
    let target = cluster.agent_on(vec![2, 3, 4]);
    if cluster.leader(target) == 3 {
        cluster.stop(3);
        wait_until("another leads", || {
            cluster.running().any(|(_, node)| node.leads(target))
        });
        cluster.start(3);
    }
    let leader = cluster.leader(target);
    assert_ne!(leader, 3);
    // Caught up, node 3 follows the leader, and knows where to relay.
    wait_until("node 3 follows", || {
        cluster.node(3).applied(target).is_some()
            && cluster.node(3).applied(target) == cluster.node(leader).applied(target)
    });
    cluster.forward_once(sender, 1, target, 11);
    cluster.delivered((sender, &[1]), (target, &[2, 3, 4]), 11);
    assert!(
        cluster.node(3).messages_relayed() > 0,
        "node 3 relayed nothing"
    );
}
