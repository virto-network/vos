//! Replicated agents on nodes in one process, joined through a hub, each
//! with its own clock: creation and the directory, calls at the leader
//! applied on every replica alike, leader changes, a partitioned follower
//! catching up, and restarts.

use std::sync::Arc;
use std::time::{Duration, Instant};

use vos_net::memory::Hub;
use vos_node::store::{Batch as _, Durability, EntryKind, Fjall, Store, View};
use vos_node::{CallError, Config, Hooks, Node, Peers, Reply, Space, SpaceNode};
use vos_wire::abi::refusal;
use vos_wire::batch::{Batch, Input, Message, Request};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, Session};
use vos_wire::ingress::{Contact, NodeId, Unplaced};
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
    /// Compaction every so many entries, keeping a tail, and snapshot
    /// chunks of about so many bytes, when not the defaults.
    compaction: Option<(u64, u64, usize)>,
    /// The election timeout's range, when not the fast one.
    election_timeout_ms: Option<(u64, u64)>,
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
            compaction: None,
            election_timeout_ms: None,
        };
        cluster.grow(count);
        cluster
    }

    /// Nodes that compact their logs every few entries, and send
    /// snapshots in small chunks.
    fn compacting(count: u8) -> Self {
        let mut cluster = Self::build(0, Arc::new(vos_node::NoHooks), Vec::new(), false);
        cluster.compaction = Some((8, 2, 64));
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
        config.election_timeout_ms = self.election_timeout_ms.unwrap_or((40, 80));
        config.heartbeat_ms = 10;
        if let Some((every, tail, chunk)) = self.compaction {
            config.compact_every = every;
            config.compact_tail = tail;
            config.snapshot_chunk = chunk;
        }
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

/// Where `agent`'s log on `node` starts: the index it was compacted
/// through, or a snapshot installed at.
fn log_start(node: &Node, agent: AgentId) -> u64 {
    node.store().raft(agent).unwrap().log_start.0
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

#[test]
fn every_replica_compacts_its_log_as_it_applies() {
    let cluster = Cluster::compacting(3);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    let mut total = 0;
    for sequence in 1..=40 {
        total += sequence;
        assert_eq!(
            done(cluster.increment(leader, agent, sequence, sequence)),
            total
        );
    }
    cluster.converged(agent);
    wait_until("every replica compacts", || {
        cluster.running().all(|(_, node)| {
            let rows = node.store().raft(agent).unwrap();
            rows.log_start.0 > 20 && rows.log.len() < 20
        })
    });
}

/// A follower down while the log is compacted past it catches up by a
/// snapshot, under load: the same state, last result and pins, the
/// program it missed fetched before the switch, and its queries answer
/// the same.
#[test]
fn a_follower_behind_the_log_catches_up_by_a_snapshot() {
    let mut cluster = Cluster::compacting(3);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    let leader = cluster.leader(agent);
    let follower = (1..=3).find(|number| *number != leader).unwrap();
    wait_until("the follower runs the group", || {
        cluster.node(follower).applied(agent).is_some()
    });
    cluster.stop(follower);
    cluster.install(agent);
    let mut total = 0;
    for sequence in 1..=30 {
        total += sequence;
        assert_eq!(
            done(cluster.increment(leader, agent, sequence, sequence)),
            total
        );
    }
    wait_until("the leader compacts", || {
        log_start(cluster.node(leader), agent) > 20
    });
    cluster.start(follower);
    // Calls go on while it catches up.
    std::thread::scope(|scope| {
        let cluster = &cluster;
        scope.spawn(move || {
            let mut total = total;
            for sequence in 31..=60 {
                total += sequence;
                assert_eq!(
                    done(cluster.increment(leader, agent, sequence, sequence)),
                    total
                );
            }
        });
    });
    cluster.converged(agent);
    let caught_up = cluster.node(follower);
    assert!(log_start(caught_up, agent) > 20, "installed a snapshot");
    assert_eq!(caught_up.pinned(), cluster.node(leader).pinned());
    assert!(!caught_up.pinned().is_empty(), "the program it missed");
    let last = |node: &Node| node.store().snapshot().last_result(agent).unwrap();
    assert_eq!(last(caught_up), last(cluster.node(leader)));
    assert_eq!(cluster.value(follower, agent), (1..=60).sum::<u64>());
    assert!(
        caught_up.store().stale_epochs(agent).unwrap().is_empty(),
        "the old epoch is dropped"
    );
}

/// A replica that caught up by a snapshot holds the sessions with it: once
/// it leads, a call it never ran is answered from the window.
#[test]
fn a_replica_caught_up_by_a_snapshot_answers_from_its_window_when_it_leads() {
    let mut cluster = Cluster::compacting(3);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    let follower = (1..=3).find(|number| *number != leader).unwrap();
    cluster.stop(follower);
    let mut total = 0;
    for sequence in 1..=30 {
        total += sequence;
        assert_eq!(
            done(cluster.increment(leader, agent, sequence, sequence)),
            total
        );
    }
    wait_until("the leader compacts", || {
        log_start(cluster.node(leader), agent) > 20
    });
    cluster.start(follower);
    cluster.converged(agent);
    assert!(log_start(cluster.node(follower), agent) > 20);
    // Leadership moves until it reaches the replica that caught up.
    let until = Instant::now() + Duration::from_secs(20);
    while cluster.leader(agent) != follower {
        assert!(Instant::now() < until, "it never led");
        let current = cluster.leader(agent);
        cluster.stop(current);
        wait_until("another leader", || {
            cluster
                .running()
                .any(|(number, node)| number != current && node.leads(agent))
        });
        cluster.start(current);
        cluster.converged(agent);
    }
    assert_eq!(done(cluster.increment(follower, agent, 30, 30)), total);
    assert_eq!(cluster.value(follower, agent), total);
}

/// A snapshot cut short, by its follower stopping or its leader stopping,
/// still ends in one: the follower holds the same state, and no staged
/// rows are left behind.
#[test]
fn a_snapshot_cut_short_is_sent_again() {
    let mut cluster = Cluster::compacting(3);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    let follower = (1..=3).find(|number| *number != leader).unwrap();
    cluster.stop(follower);
    // Enough rows for many chunks.
    for sequence in 1..=60 {
        done(cluster.increment(leader, agent, sequence, sequence));
    }
    wait_until("the leader compacts", || {
        log_start(cluster.node(leader), agent) > 40
    });
    // Its follower stops while it stages.
    cluster.start(follower);
    std::thread::sleep(Duration::from_millis(15));
    cluster.stop(follower);
    cluster.start(follower);
    // Its leader stops while it streams.
    std::thread::sleep(Duration::from_millis(15));
    cluster.stop(leader);
    cluster.start(leader);
    cluster.converged(agent);
    assert_eq!(cluster.value(follower, agent), (1..=60).sum::<u64>());
    wait_until("no staged rows are left", || {
        cluster
            .running()
            .all(|(_, node)| node.store().stale_epochs(agent).unwrap().is_empty())
    });
}

/// A snapshot switches only once the programs it names are here: while
/// every node withholds them, the follower stays behind.
#[test]
fn a_snapshot_waits_for_the_programs_it_names() {
    let withheld = Arc::new(WithholdBlobs(std::sync::atomic::AtomicBool::new(false)));
    let mut cluster = Cluster::build(0, withheld.clone(), Vec::new(), false);
    cluster.compaction = Some((8, 2, 64));
    cluster.grow(3);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    let leader = cluster.leader(agent);
    let follower = (1..=3).find(|number| *number != leader).unwrap();
    wait_until("the follower runs the group", || {
        cluster.node(follower).applied(agent).is_some()
    });
    cluster.stop(follower);
    cluster.install(agent);
    for sequence in 1..=30 {
        done(cluster.increment(leader, agent, sequence, sequence));
    }
    wait_until("the leader compacts", || {
        log_start(cluster.node(leader), agent) > 20
    });
    withheld.0.store(true, std::sync::atomic::Ordering::SeqCst);
    cluster.start(follower);
    wait_until("the follower stages the snapshot", || {
        !cluster
            .node(follower)
            .store()
            .stale_epochs(agent)
            .unwrap()
            .is_empty()
    });
    // Time for every chunk to arrive.
    std::thread::sleep(Duration::from_millis(500));
    assert_eq!(
        log_start(cluster.node(follower), agent),
        0,
        "switched without the program"
    );
    assert!(cluster.node(follower).pinned().is_empty());
    withheld.0.store(false, std::sync::atomic::Ordering::SeqCst);
    cluster.converged(agent);
    assert_eq!(
        cluster.node(follower).pinned(),
        cluster.node(leader).pinned()
    );
}

/// Every running node holds `placement`'s replicas for `agent`, committed
/// and final.
fn placed(cluster: &Cluster, agent: AgentId, replicas: &[NodeNumber]) {
    wait_until("every node holds the final placement", || {
        cluster.running().all(|(_, node)| {
            node.placement(agent).is_some_and(|placement| {
                placement.replicas == replicas && placement.committed && !placement.joint
            })
        })
    });
}

/// A node no longer replicating `agent` runs no group for it and keeps
/// none of its state or log.
fn retired(node: &Node, agent: AgentId) {
    wait_until("the replica retires", || {
        node.applied(agent).is_none()
            && rows(node, agent).is_empty()
            && node.store().raft(agent).unwrap().log.is_empty()
    });
}

/// One replica replaced by another node while calls go on: the new one
/// catches up, every node holds the new placement, the old replica keeps
/// nothing and does not come back after a restart.
#[test]
fn a_replica_is_replaced_under_load() {
    let mut cluster = Cluster::compacting(4);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    let removed = (1..=3).find(|number| *number != leader).unwrap();
    for sequence in 1..=30 {
        done(cluster.increment(leader, agent, sequence, sequence));
    }
    let mut replicas: Vec<NodeNumber> = (1..=3)
        .filter(|number| *number != removed)
        .chain([4])
        .collect();
    replicas.sort_unstable();
    std::thread::scope(|scope| {
        let cluster = &cluster;
        scope.spawn(move || {
            for sequence in 31..=60 {
                done(cluster.increment(leader, agent, sequence, sequence));
            }
        });
        assert_eq!(
            cluster.node(leader).replace(agent, removed, 4).unwrap(),
            replicas
        );
    });
    placed(&cluster, agent, &replicas);
    retired(cluster.node(removed), agent);
    cluster.converged(agent);
    assert_eq!(cluster.value(4, agent), (1..=60).sum::<u64>());
    cluster.stop(removed);
    cluster.start(removed);
    std::thread::sleep(Duration::from_millis(300));
    assert!(cluster.node(removed).applied(agent).is_none());
    // Clients learn the replicas from any node.
    let info = cluster
        .node(removed)
        .placement(agent)
        .expect("the placement");
    assert_eq!(info.replicas, replicas);
}

/// After a replacement, the group compacts its log again and takes the
/// next change, though the replica it removed retired without
/// acknowledging the change to the group. Here the leader removes itself,
/// then its successor replaces another replica.
#[test]
fn a_replacement_leaves_the_group_free_to_change_and_compact() {
    let cluster = Cluster::compacting(5);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    for sequence in 1..=10 {
        done(cluster.increment(leader, agent, sequence, 1));
    }
    let mut replicas: Vec<NodeNumber> = (1..=3)
        .filter(|number| *number != leader)
        .chain([4])
        .collect();
    replicas.sort_unstable();
    assert_eq!(
        cluster.node(leader).replace(agent, leader, 4).unwrap(),
        replicas
    );
    retired(cluster.node(leader), agent);
    let next = cluster.leader(agent);
    let start = log_start(cluster.node(next), agent);
    for sequence in 11..=40 {
        done(cluster.increment(next, agent, sequence, 1));
    }
    assert!(
        log_start(cluster.node(next), agent) > start,
        "compacting again"
    );
    let removed = *replicas.iter().find(|number| **number != next).unwrap();
    let mut after: Vec<NodeNumber> = replicas
        .iter()
        .copied()
        .filter(|number| *number != removed)
        .chain([5])
        .collect();
    after.sort_unstable();
    assert_eq!(
        cluster.node(next).replace(agent, removed, 5).unwrap(),
        after
    );
    placed(&cluster, agent, &after);
    cluster.converged(agent);
}

/// A replica down for good does not hold the group up once it is
/// replaced: the group compacts and takes the next change without it.
#[test]
fn a_replica_replaced_while_down_holds_nothing_up() {
    let mut cluster = Cluster::compacting(5);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    let mut followers = (1..=3).filter(|number| *number != leader);
    let (gone, other) = (followers.next().unwrap(), followers.next().unwrap());
    cluster.stop(gone);
    cluster.node(leader).replace(agent, gone, 4).unwrap();
    let start = log_start(cluster.node(leader), agent);
    for sequence in 1..=30 {
        done(cluster.increment(leader, agent, sequence, 1));
    }
    assert!(log_start(cluster.node(leader), agent) > start);
    let mut after = vec![leader, 4, 5];
    after.sort_unstable();
    assert_eq!(
        cluster.node(leader).replace(agent, other, 5).unwrap(),
        after
    );
    placed(&cluster, agent, &after);
}

/// A leader that removed itself and retired keeps its committed
/// placement when a later leader announces the same configuration before
/// it learns that it committed, naming the old leader among the nodes
/// before: the old leader does not start the group again.
#[test]
fn a_retired_leader_keeps_its_committed_placement() {
    let mut cluster = Cluster::new(4);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    cluster.node(leader).replace(agent, leader, 4).unwrap();
    retired(cluster.node(leader), agent);
    let next = cluster.leader(agent);
    // Settled once the next leader has confirmed the removal and announced
    // it: the same committed placement on both, twice in a row.
    let settled = || {
        let held = cluster.node(leader).placement(agent)?;
        (held.committed && Some(&held) == cluster.node(next).placement(agent).as_ref())
            .then_some(held)
    };
    let mut held = None;
    wait_until("the placements settle", || {
        let first = settled();
        std::thread::sleep(Duration::from_millis(200));
        held = first.filter(|first| settled().as_ref() == Some(first));
        held.is_some()
    });
    let held = held.unwrap();
    let record = cluster
        .node(leader)
        .store()
        .agents()
        .unwrap()
        .into_iter()
        .find(|record| record.agent == agent)
        .unwrap();
    // One of the replicas, stopped, speaks for it.
    let replica = *held
        .replicas
        .iter()
        .find(|number| **number != next)
        .unwrap();
    cluster.stop(replica);
    let (sender, _arrivals) = cluster.hub.join(replica);
    vos_net::Network::set_peers(&sender, cluster.space.peers());
    let message = PeerMessage::Directory {
        record,
        placement: vos_wire::peer::Placement {
            before: [held.before.clone(), vec![leader]].concat(),
            term: held.term + 5,
            committed: false,
            ..held.clone()
        },
    };
    vos_net::Network::send(
        &sender,
        leader,
        vos_net::Class::Requests,
        u64::from(agent.0),
        message.encode(),
    )
    .unwrap();
    std::thread::sleep(Duration::from_millis(300));
    assert!(cluster.node(leader).applied(agent).is_none());
    let kept = cluster.node(leader).placement(agent).unwrap();
    assert!(kept.committed && kept.term < held.term + 5 && !kept.admits(leader));
}

/// The leader replaces itself: it finalizes the change, steps down and
/// retires, and the agent goes on under a new leader.
#[test]
fn the_leader_replaces_itself() {
    let cluster = Cluster::new(4);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    assert_eq!(done(cluster.increment(leader, agent, 1, 5)), 5);
    let mut replicas: Vec<NodeNumber> = (1..=3)
        .filter(|number| *number != leader)
        .chain([4])
        .collect();
    replicas.sort_unstable();
    assert_eq!(
        cluster.node(leader).replace(agent, leader, 4).unwrap(),
        replicas
    );
    placed(&cluster, agent, &replicas);
    retired(cluster.node(leader), agent);
    let next = cluster.leader(agent);
    assert_ne!(next, leader);
    assert_eq!(done(cluster.increment(next, agent, 2, 1)), 6);
    cluster.converged(agent);
}

/// With elections as slow as a deployment's, a leader replacing itself
/// is answered without waiting for the next leader: it says where the
/// agent runs as it steps down.
#[test]
fn a_leader_replacing_itself_is_answered_before_the_next_election() {
    let mut cluster = Cluster::build(0, Arc::new(vos_node::NoHooks), Vec::new(), false);
    cluster.election_timeout_ms = Some((2500, 3000));
    cluster.grow(4);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    let mut replicas: Vec<NodeNumber> = (1..=3)
        .filter(|number| *number != leader)
        .chain([4])
        .collect();
    replicas.sort_unstable();
    assert_eq!(
        cluster.node(leader).replace(agent, leader, 4).unwrap(),
        replicas
    );
    placed(&cluster, agent, &replicas);
    retired(cluster.node(leader), agent);
}

/// A retirement a crash cut short: the node holds the placement that no
/// longer names it, and its replica's log and state. Started cut off from
/// every other node, it finishes the retirement on its own.
#[test]
fn a_retirement_cut_short_finishes_at_the_next_start() {
    let mut cluster = Cluster::new(4);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    let removed = (1..=3).find(|number| *number != leader).unwrap();
    assert_eq!(done(cluster.increment(leader, agent, 1, 3)), 3);
    cluster.converged(agent);
    cluster.stop(removed);
    cluster.node(leader).replace(agent, removed, 4).unwrap();
    let placement = cluster.node(leader).placement(agent).unwrap();
    {
        let store =
            Fjall::open(cluster.dirs[usize::from(removed) - 1].path().join("store")).unwrap();
        assert!(
            store.raft(agent).unwrap().applied > 0,
            "the replica's state"
        );
        let mut batch = store.batch();
        batch.placement(agent, &placement);
        batch.commit(Durability::Synced).unwrap();
    }
    cluster.hub.isolate(removed);
    cluster.start(removed);
    retired(cluster.node(removed), agent);
    wait_until("the old epoch is dropped", || {
        cluster
            .node(removed)
            .store()
            .stale_epochs(agent)
            .unwrap()
            .is_empty()
    });
}

/// A leader cut off before its joint configuration reaches a majority
/// announces it to the node it would add, which starts the group; the
/// next leader's placement outranks it, and that node stops. A second
/// replacement, at the next leader, then succeeds.
#[test]
fn a_phantom_placement_gives_way_to_the_next_leader() {
    let cluster = Cluster::new(4);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    let followers: Vec<NodeNumber> = (1..=3).filter(|number| *number != leader).collect();
    for follower in &followers {
        cluster.hub.partition(leader, *follower);
    }
    std::thread::scope(|scope| {
        let cluster = &cluster;
        let gone = followers[1];
        let replaced = scope.spawn(move || cluster.node(leader).replace(agent, gone, 4));
        wait_until("the node it would add starts the group", || {
            cluster.node(4).applied(agent).is_some()
        });
        assert!(replaced.join().unwrap().is_err(), "never committed");
    });
    let next = loop {
        let next = cluster.leader(agent);
        if next != leader {
            break next;
        }
    };
    retired(cluster.node(4), agent);
    cluster.hub.heal();
    let mut replicas = vec![leader, followers[0], 4];
    replicas.sort_unstable();
    assert_eq!(
        cluster.node(next).replace(agent, followers[1], 4).unwrap(),
        replicas
    );
    placed(&cluster, agent, &replicas);
    cluster.converged(agent);
}

/// The leader cut off once its joint configuration committed, as it
/// appends the final one: the next leader finalizes the change, and says
/// so.
#[test]
fn the_next_leader_finalizes_a_joint_configuration() {
    let cluster = Cluster::new(4);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    let removed = (1..=3).find(|number| *number != leader).unwrap();
    std::thread::scope(|scope| {
        let cluster = &cluster;
        scope.spawn(move || {
            let _ = cluster.node(leader).replace(agent, removed, 4);
        });
        // The core appends the final configuration once the joint one
        // commits.
        wait_until("the final configuration is appended", || {
            cluster
                .node(leader)
                .placement(agent)
                .is_some_and(|placement| placement.replicas.contains(&4) && !placement.joint)
        });
        cluster.hub.isolate(leader);
    });
    let mut replicas: Vec<NodeNumber> = (1..=3)
        .filter(|number| *number != removed)
        .chain([4])
        .collect();
    replicas.sort_unstable();
    wait_until("the final placement elsewhere", || {
        cluster
            .running()
            .filter(|(number, _)| *number != leader)
            .all(|(_, node)| {
                node.placement(agent).is_some_and(|placement| {
                    placement.replicas == replicas && placement.committed && !placement.joint
                })
            })
    });
    cluster.hub.heal();
    placed(&cluster, agent, &replicas);
    retired(cluster.node(removed), agent);
}

/// A replica down while it is replaced comes back with its old log: it
/// does not disturb the group, and retires once it hears where the agent
/// runs.
#[test]
fn a_removed_replica_back_with_its_old_log_disturbs_nothing() {
    let mut cluster = Cluster::new(4);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let leader = cluster.leader(agent);
    let removed = (1..=3).find(|number| *number != leader).unwrap();
    assert_eq!(done(cluster.increment(leader, agent, 1, 3)), 3);
    cluster.converged(agent);
    cluster.stop(removed);
    let mut replicas: Vec<NodeNumber> = (1..=3)
        .filter(|number| *number != removed)
        .chain([4])
        .collect();
    replicas.sort_unstable();
    assert_eq!(
        cluster.node(leader).replace(agent, removed, 4).unwrap(),
        replicas
    );
    let term = |cluster: &Cluster| cluster.node(leader).store().raft(agent).unwrap().hard.term;
    let before = term(&cluster);
    cluster.start(removed);
    retired(cluster.node(removed), agent);
    assert_eq!(cluster.leader(agent), leader);
    assert_eq!(term(&cluster), before, "no election");
    placed(&cluster, agent, &replicas);
}

/// A node that cannot run the agent's program is refused before the
/// group's configuration changes.
#[test]
fn a_replacement_by_a_node_that_cannot_run_the_program_is_refused() {
    let programs = Programs::load();
    let cluster = Cluster::with(
        4,
        Arc::new(vos_node::NoHooks),
        vec![None, None, None, Some(programs.counter.clone())],
    );
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    let leader = cluster.leader(agent);
    let removed = (1..=3).find(|number| *number != leader).unwrap();
    assert!(matches!(
        cluster.node(leader).replace(agent, removed, 4),
        Err(vos_node::ReplaceError::Unplaced(Unplaced::CannotRun))
    ));
    let placement = cluster.node(leader).placement(agent).unwrap();
    assert_eq!(placement.replicas, vec![1, 2, 3]);
    assert!(!placement.joint);
}

/// `count` agents on nodes 1 to 3, each with a leader.
fn agents(cluster: &Cluster, count: usize) -> Vec<AgentId> {
    let agents: Vec<AgentId> = (0..count)
        .map(|_| cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap())
        .collect();
    for &agent in &agents {
        cluster.leader(agent);
    }
    agents
}

/// Each agent's term, as the highest any running replica holds.
fn terms(cluster: &Cluster, agents: &[AgentId]) -> Vec<u64> {
    agents
        .iter()
        .map(|&agent| {
            cluster
                .running()
                .map(|(_, node)| node.store().raft(agent).unwrap().hard.term)
                .max()
                .unwrap()
        })
        .collect()
}

/// Groups at rest send each other nothing: the pair heartbeat vouches for
/// their leaders. A call to one goes through at once.
#[test]
fn idle_groups_send_nothing_but_the_pair_heartbeat() {
    let cluster = slow_elections(3);
    let agents = agents(&cluster, 100);
    cluster.install(agents[0]);
    let at = |cluster: &Cluster| {
        (
            cluster.hub.sent(vos_net::Class::Consensus),
            cluster.hub.sent(vos_net::Class::Liveness),
        )
    };
    // Settled once a stretch of several election timeouts passes quietly.
    let mut quiet = false;
    for _ in 0..20 {
        let before = at(&cluster);
        std::thread::sleep(Duration::from_millis(500));
        let after = at(&cluster);
        assert!(after.1 > before.1, "pair heartbeats go on");
        if after.0 == before.0 {
            quiet = true;
            break;
        }
    }
    assert!(quiet, "the groups never went quiet");
    let terms_before = terms(&cluster, &agents);
    let leader = cluster.leader(agents[0]);
    assert_eq!(done(cluster.increment(leader, agents[0], 1, 4)), 4);
    assert_eq!(terms(&cluster, &agents), terms_before);
}

/// The node leading many quiet groups stops: each group elects another
/// leader, as fast as an election timeout after its last pair heartbeat
/// allows.
#[test]
fn quiet_groups_elect_again_when_their_leaders_node_stops() {
    let mut cluster = slow_elections(3);
    let agents = agents(&cluster, 60);
    let mut led = [0usize; 4];
    for &agent in &agents {
        led[usize::from(cluster.leader(agent))] += 1;
    }
    let gone = (1..=3).max_by_key(|&number| led[number]).unwrap() as NodeNumber;
    std::thread::sleep(Duration::from_millis(300));
    let stopped = Instant::now();
    cluster.stop(gone);
    for &agent in &agents {
        cluster.leader(agent);
    }
    let took = stopped.elapsed();
    eprintln!(
        "{} groups led by node {gone} elected again within {took:?}",
        led[usize::from(gone)]
    );
    assert!(took < Duration::from_secs(5), "{took:?}");
    // Back, its new run is heard, and every group goes quiet again with
    // no term moving.
    cluster.start(gone);
    let mut quiet = false;
    for _ in 0..20 {
        let before = terms(&cluster, &agents);
        let sent = cluster.hub.sent(vos_net::Class::Consensus);
        std::thread::sleep(Duration::from_millis(500));
        if cluster.hub.sent(vos_net::Class::Consensus) == sent {
            assert_eq!(terms(&cluster, &agents), before);
            quiet = true;
            break;
        }
    }
    assert!(quiet, "the groups never went quiet again");
}

/// Nodes 1 to `count` with elections of 300–600 ms: slow enough that a
/// loaded machine does not let the pair heartbeat lapse.
fn slow_elections(count: u8) -> Cluster {
    let mut cluster = Cluster::build(0, Arc::new(vos_node::NoHooks), Vec::new(), false);
    cluster.election_timeout_ms = Some((300, 600));
    cluster.grow(count);
    cluster
}

/// A follower node restarted while its groups are quiet, nothing written
/// meanwhile, hears its leaders at once: each probes it on hearing its
/// new run, rather than waiting for its own deadline (a second or more
/// here) to draw a heartbeat.
#[test]
fn a_restarted_follower_hears_its_quiet_leaders_at_once() {
    let mut cluster = Cluster::build(0, Arc::new(vos_node::NoHooks), Vec::new(), false);
    cluster.election_timeout_ms = Some((1_000, 2_000));
    cluster.grow(3);
    let agents = agents(&cluster, 12);
    let follower = 3;
    let followed: Vec<AgentId> = agents
        .iter()
        .copied()
        .filter(|&agent| cluster.leader(agent) != follower)
        .collect();
    std::thread::sleep(Duration::from_millis(500));
    cluster.stop(follower);
    std::thread::sleep(Duration::from_millis(200));
    cluster.start(follower);
    let started = Instant::now();
    for &agent in &followed {
        let request = Request {
            session: cluster.session,
            sequence: 1,
            caller: ALICE,
            instance: COUNTER,
            method: cluster.programs.method("increment"),
            arguments: 1u64.encode(),
        };
        let reply = smol::block_on(cluster.node(follower).call(agent, request));
        assert!(
            matches!(reply, Err(CallError::NotLeader(Some(_)))),
            "{reply:?}"
        );
    }
    let took = started.elapsed();
    eprintln!(
        "{} groups heard their leaders within {took:?}",
        followed.len()
    );
    assert!(took < Duration::from_millis(800), "{took:?}");
}

/// A follower node restarted catches up its quiet groups.
#[test]
fn a_restarted_follower_catches_up_its_quiet_groups() {
    let mut cluster = Cluster::new(3);
    let agents = agents(&cluster, 12);
    let installed = &agents[..4];
    for &agent in installed {
        cluster.install(agent);
    }
    let leaders: Vec<NodeNumber> = installed
        .iter()
        .map(|&agent| cluster.leader(agent))
        .collect();
    // A node leading none of them, or else the one leading the fewest,
    // whose own are left out.
    let follower = (1..=3)
        .min_by_key(|number| leaders.iter().filter(|leader| *leader == number).count())
        .unwrap();
    let installed: Vec<AgentId> = installed
        .iter()
        .zip(&leaders)
        .filter(|(_, leader)| **leader != follower)
        .map(|(agent, _)| *agent)
        .collect();
    let leaders: Vec<NodeNumber> = leaders
        .into_iter()
        .filter(|leader| *leader != follower)
        .collect();
    let installed = &installed[..];
    cluster.stop(follower);
    for (&agent, &leader) in installed.iter().zip(&leaders) {
        if leader != follower {
            assert_eq!(done(cluster.increment(leader, agent, 1, 2)), 2);
        }
    }
    cluster.start(follower);
    for &agent in installed {
        cluster.converged(agent);
    }
}

/// A link losing half its frames, then a link cut, moves no group's term:
/// the follower that stops hearing its leader is refused by the other,
/// which the pair heartbeat still vouches to.
#[test]
fn a_flaky_then_cut_link_moves_no_term() {
    let mut cluster = Cluster::build(0, Arc::new(vos_node::NoHooks), Vec::new(), false);
    cluster.election_timeout_ms = Some((300, 600));
    cluster.grow(3);
    let agents = agents(&cluster, 40);
    cluster.install(agents[0]);
    std::thread::sleep(Duration::from_millis(1_000));
    let before = terms(&cluster, &agents);
    // Lossy enough that the vouches between 1 and 2 lapse now and then.
    cluster.hub.set_link_loss(1, 2, 950_000);
    std::thread::sleep(Duration::from_secs(3));
    cluster.hub.heal();
    cluster.hub.partition(1, 2);
    std::thread::sleep(Duration::from_secs(3));
    cluster.hub.heal();
    std::thread::sleep(Duration::from_millis(1_000));
    assert_eq!(terms(&cluster, &agents), before);
    let leader = cluster.leader(agents[0]);
    assert_eq!(done(cluster.increment(leader, agents[0], 1, 7)), 7);
}

/// Holds every commit while asked.
struct HoldCommits(std::sync::atomic::AtomicBool);

impl Hooks for HoldCommits {
    fn before_commit(&self) {
        while self.0.load(std::sync::atomic::Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

/// Lets held commits go when dropped, even by a failing assertion, so the
/// call waiting on them returns.
struct Release<'a>(&'a std::sync::atomic::AtomicBool);

impl Drop for Release<'_> {
    fn drop(&mut self) {
        self.0.store(false, std::sync::atomic::Ordering::Relaxed);
    }
}

/// A node whose writer stalls stops being vouched for: the quiet groups
/// it leads elect leaders elsewhere.
#[test]
fn the_groups_of_a_node_whose_writer_stalls_elect_elsewhere() {
    let hold = Arc::new(HoldCommits(std::sync::atomic::AtomicBool::new(false)));
    let cluster = Cluster::with_node_hooks(vec![
        Arc::clone(&hold) as Arc<dyn Hooks>,
        Arc::new(vos_node::NoHooks),
        Arc::new(vos_node::NoHooks),
    ]);
    let agents = agents(&cluster, 30);
    for &agent in &agents {
        cluster.install(agent);
    }
    // Node 1 leads some; one of them takes a call its writer holds.
    let led: Vec<AgentId> = loop {
        let led: Vec<AgentId> = agents
            .iter()
            .copied()
            .filter(|&agent| cluster.leader(agent) == 1)
            .collect();
        if !led.is_empty() {
            break led;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    hold.0.store(true, std::sync::atomic::Ordering::Relaxed);
    std::thread::scope(|scope| {
        let _release = Release(&hold.0);
        let cluster = &cluster;
        let held = led[0];
        let call = scope.spawn(move || cluster.increment(1, held, 1, 1));
        // The group whose driver waits on the held write still believes
        // it leads, until the write returns.
        wait_until("another node leads each group node 1 led", || {
            led.iter()
                .all(|&agent| cluster.node(2).leads(agent) || cluster.node(3).leads(agent))
        });
        drop(_release);
        let _ = call.join();
    });
    for &agent in &led {
        assert_ne!(cluster.leader(agent), 1);
    }
}

/// A leader that still believes it leads, though its followers elected
/// another that replaced it, retires once it hears the committed final
/// placement: its Raft frames, both ways, and its pair heartbeat to its
/// followers are lost, while it still hears theirs.
#[test]
fn a_stale_leader_left_out_of_the_configuration_retires() {
    let cluster = Cluster::new(4);
    let agent = cluster.node(1).create_replicated(vec![1, 2, 3]).unwrap();
    cluster.install(agent);
    let stale = cluster.leader(agent);
    let followers: Vec<NodeNumber> = (1..=3).filter(|number| *number != stale).collect();
    for &follower in &followers {
        cluster
            .hub
            .cut_class(stale, follower, vos_net::Class::Consensus);
        cluster
            .hub
            .cut_class(follower, stale, vos_net::Class::Consensus);
        cluster
            .hub
            .cut_class(stale, follower, vos_net::Class::Liveness);
    }
    let next = loop {
        let leading: Vec<NodeNumber> = followers
            .iter()
            .copied()
            .filter(|number| cluster.node(*number).leads(agent))
            .collect();
        if let [next] = leading[..] {
            break next;
        }
        std::thread::sleep(Duration::from_millis(5));
    };
    assert!(
        cluster.node(stale).leads(agent),
        "the stale one still leads"
    );
    let mut replicas: Vec<NodeNumber> = followers.iter().copied().chain([4]).collect();
    replicas.sort_unstable();
    assert_eq!(
        cluster.node(next).replace(agent, stale, 4).unwrap(),
        replicas
    );
    cluster.hub.heal();
    retired(cluster.node(stale), agent);
}
