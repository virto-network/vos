//! Exactly once, over HTTP, through failures: clients increment counters
//! on three nodes, two at each agent, each request resent with its
//! sequence until answered, in sessions they start every few dozen
//! requests, while the nodes stop and start, a leader stops between its
//! apply and its answer, a node is cut off, the network loses and delays
//! frames, a node's clock jumps, and every clock jumps past the skew.
//! Once a run every session expires and is collected while a leader
//! stops, and requests captured before, run or not, are sent again.
//!
//! Every answer must be its client's running total: no request applied
//! twice, none skipped. A node must hold a request applied before it
//! answers it, a captured request never runs, and at the end every
//! replica holds every request once.
//!
//! The seed is printed; `EXACTLY_ONCE_SEED` runs one again.

/// The allocator the node's binary runs on.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use vos_checker::{
    ANSWERED, ATTEMPT, COUNTER, Client, INBOX, Log, Methods, Mode, Nodes, Random, SECOND,
    wait_until,
};
use vos_net::memory::Hub;
use vos_node::client::Target;
use vos_node::store::{Store, View};
use vos_node::{Config, Hooks, Node, Peers, Space, SpaceNode};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, Session, SessionId};
use vos_wire::ingress::{
    Answer, Call, Consistency, QueryCall, Rejection, call_message, query_message,
};
use vos_wire::peer::NodeNumber;
use vos_wire::records::{SessionMark, unstored};
use vos_wire::result::Outcome;
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode, defaults, keys};

/// How far one node's clock jumps, either way.
const NODE_JUMP: i64 = 15_000;
/// How far every clock jumps ahead, once a run: past the skew and both
/// ways of a node's jump, with 30 s to spare.
const CLUSTER_JUMP: i64 = 120_000;
const _: () = assert!(CLUSTER_JUMP >= defaults::SESSION_SKEW_MS as i64 + 2 * NODE_JUMP + 30_000);
const NODES: NodeNumber = 3;
/// Failures a run goes through; clients send until they are over.
const FAULTS: usize = 16;

fn elf(path: &str) -> Vec<u8> {
    let path = format!("{}/../../agent/{path}", env!("CARGO_MANIFEST_DIR"));
    let elf = std::fs::read(&path).unwrap_or_else(|error| {
        panic!("{path}: {error}; run `just build-agent build-test-actors`")
    });
    vos_pvm_compiler::link_elf_spi(&elf).expect("links")
}

fn method(program: &[u8], name: &str) -> MethodId {
    let parsed = vos_pvm::spi::parse_standard_program(program).unwrap();
    Schema::read(&parsed.ro_data)
        .unwrap()
        .methods
        .iter()
        .find(|method| method.name == name.as_bytes())
        .unwrap_or_else(|| panic!("no method {name}"))
        .id
}

/// Stops a leader loop once, after its commit and before its answers; and
/// holds the node's refines, or its commits, while asked.
#[derive(Default)]
struct Trip {
    armed: AtomicBool,
    tripped: AtomicBool,
    refines: Gate,
    commits: Gate,
}

/// Holds whoever passes while it is closed, counting them.
#[derive(Default)]
struct Gate {
    closed: Mutex<bool>,
    opened: std::sync::Condvar,
    reached: AtomicU64,
}

impl Gate {
    fn pass(&self) {
        let mut closed = self.closed.lock().unwrap();
        if *closed {
            self.reached.fetch_add(1, Ordering::SeqCst);
        }
        while *closed {
            closed = self.opened.wait(closed).unwrap();
        }
    }

    /// Close the gate until what this gives back is dropped, a failing
    /// test's included.
    fn close(&self) -> Closed<'_> {
        *self.closed.lock().unwrap() = true;
        Closed(self)
    }

    fn open(&self) {
        *self.closed.lock().unwrap() = false;
        self.opened.notify_all();
    }
}

struct Closed<'a>(&'a Gate);

impl Drop for Closed<'_> {
    fn drop(&mut self) {
        self.0.open();
    }
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

/// One node's slot: its node while it runs, how often it started, its
/// hook and its clock's offset.
struct Slot {
    node: Mutex<Option<Arc<Node>>>,
    starts: AtomicU64,
    /// Messages its earlier runs sent across nodes.
    sent_across: AtomicU64,
    /// Snapshots its earlier runs switched to.
    installed: AtomicU64,
    trip: Arc<Trip>,
    offset: Arc<AtomicI64>,
    dir: tempfile::TempDir,
    ingress: SocketAddr,
}

/// Three nodes on a hub, each serving its ingress at an address the space
/// names, so redirects reach it.
struct Cluster {
    hub: Hub,
    space: Space,
    agent: Vec<u8>,
    slots: Vec<Slot>,
    /// Each node's ingress, as clients reach it.
    targets: Vec<Target>,
    /// What happened: printed, so a run shows what it tried, and the
    /// latest events, for a failure to show what led to it.
    log: Log,
    /// How far every node's clock is ahead of the wall's, on top of its
    /// own offset; clients time their sessions and queries by it.
    offset: Arc<AtomicI64>,
    /// Clients stop at their next request while it is set.
    paused: AtomicBool,
}

impl Cluster {
    fn new(seed: u64) -> Self {
        let agent = elf("default/target/riscv64em-vos/release/vos-agent.elf");
        let mut slots = Vec::new();
        let mut nodes = Vec::new();
        for number in 1..=NODES {
            let dir = tempfile::tempdir().unwrap();
            // A first open makes the node's key.
            let node = Node::open(dir.path(), Config::new(agent.clone())).unwrap();
            let key = node.id().0;
            node.shutdown();
            // Below the ephemeral range, so no client's connection takes
            // one while its node is down.
            let free = || loop {
                use std::hash::{BuildHasher, Hasher};
                let random = std::collections::hash_map::RandomState::new()
                    .build_hasher()
                    .finish();
                let port = 20_000 + (random % 12_000) as u16;
                if let Ok(listener) = TcpListener::bind(("127.0.0.1", port)) {
                    break listener.local_addr().unwrap();
                }
            };
            let ingress = free();
            nodes.push(SpaceNode {
                number,
                key,
                peer: free(),
                ingress: format!("http://{ingress}"),
            });
            slots.push(Slot {
                node: Mutex::new(None),
                starts: AtomicU64::new(0),
                sent_across: AtomicU64::new(0),
                installed: AtomicU64::new(0),
                trip: Arc::new(Trip::default()),
                offset: Arc::new(AtomicI64::new(0)),
                dir,
                ingress,
            });
        }
        let targets = slots
            .iter()
            .map(|slot| Target::loopback(&format!("http://{}", slot.ingress)).unwrap())
            .collect();
        let cluster = Self {
            hub: Hub::new(seed),
            space: Space::new(nodes).unwrap(),
            agent,
            slots,
            targets,
            log: Log::default(),
            offset: Arc::new(AtomicI64::new(0)),
            paused: AtomicBool::new(false),
        };
        for number in 1..=NODES {
            cluster.start(number);
        }
        cluster
    }

    fn saw(&self, what: &'static str) {
        self.log.saw(what);
        if what.starts_with("fault") {
            self.log.event(format!(
                "{what}, leaders {:?}",
                self.slots
                    .iter()
                    .map(|slot| slot.node.lock().unwrap().is_some())
                    .collect::<Vec<_>>()
            ));
        }
    }

    fn slot(&self, number: NodeNumber) -> &Slot {
        &self.slots[usize::from(number) - 1]
    }

    fn start(&self, number: NodeNumber) {
        let slot = self.slot(number);
        let mut config = Config::new(self.agent.clone());
        config.executors = 2;
        config.hooks = slot.trip.clone();
        config.space = Some(self.space.clone());
        config.peers = Peers::Hub(self.hub.clone());
        config.election_timeout_ms = (40, 80);
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
        // The address the last run served is let go of with it.
        let until = Instant::now() + Duration::from_secs(5);
        while let Err(error) = node.serve(slot.ingress) {
            assert!(Instant::now() < until, "node {number}: {error:?}");
            std::thread::sleep(Duration::from_millis(10));
        }
        slot.starts.fetch_add(1, Ordering::SeqCst);
        *slot.node.lock().unwrap() = Some(Arc::new(node));
    }

    fn stop(&self, number: NodeNumber) {
        let Some(mut node) = self.slot(number).node.lock().unwrap().take() else {
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
        self.slot(number)
            .sent_across
            .fetch_add(node.messages_sent_across(), Ordering::SeqCst);
        self.slot(number)
            .installed
            .fetch_add(node.snapshots_installed(), Ordering::SeqCst);
        node.shutdown();
    }

    fn node(&self, number: NodeNumber) -> Option<Arc<Node>> {
        self.slot(number).node.lock().unwrap().clone()
    }

    /// The running node leading `agent`, if one does.
    fn leader(&self, agent: AgentId) -> Option<NodeNumber> {
        (1..=NODES).find(|number| self.node(*number).is_some_and(|node| node.leads(agent)))
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
        let snapshot = node.store().snapshot();
        let value = |key: &[u8]| {
            snapshot
                .get(agent, key)
                .unwrap()
                .map(|bytes| unstored(&bytes).expect("a stored value").to_vec())
        };
        let id = value(&keys::session_index(session))
            .map(|bytes| SessionId::decode(&bytes).unwrap().0)
            .unwrap_or_else(|| panic!("node {at} answered before it held the session"));
        let mark = SessionMark::decode(&value(&keys::session(id)).unwrap())
            .unwrap()
            .0;
        assert!(
            mark.sequence >= sequence,
            "node {at} answered sequence {sequence} at mark {}",
            mark.sequence
        );
    }
}

/// POST `body` at `address`, answered within [`ATTEMPT`].
fn post(address: SocketAddr, path: &str, body: &[u8]) -> Result<Answer, String> {
    post_within(address, path, body, ATTEMPT)
}

fn post_within(
    address: SocketAddr,
    path: &str,
    body: &[u8],
    within: Duration,
) -> Result<Answer, String> {
    let failed = |error: std::io::Error| error.to_string();
    let mut stream = TcpStream::connect_timeout(&address, within).map_err(failed)?;
    stream.set_read_timeout(Some(within)).map_err(failed)?;
    stream.set_write_timeout(Some(within)).map_err(failed)?;
    let head = format!(
        "POST {path} HTTP/1.1\r\nHost: node\r\nConnection: close\r\nContent-Length: {}\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes()).map_err(failed)?;
    stream.write_all(body).map_err(failed)?;
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).map_err(failed)?;
    let start = answer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or("an answer without a head")?;
    Answer::decode(&answer[start + 4..])
        .map(|(answer, _)| answer)
        .map_err(|_| "an answer that does not decode".to_string())
}

/// A follower of `agent` stays down until its leader has compacted the log
/// past the follower's last entry, so it comes back by a snapshot however
/// slowly the clients go (within a minute). A skip, or a minute run out, is
/// logged as such: a later missing snapshot can be traced to it.
fn follower_down_past_compaction(cluster: &Cluster, agent: AgentId) {
    let follower = || {
        let leader = cluster.leader(agent)?;
        (1..=NODES)
            .filter(|number| *number != leader)
            .find_map(|number| Some((number, cluster.node(number)?.replica(agent)?.last_index)))
    };
    let until = Instant::now() + Duration::from_secs(10);
    let (number, last) = loop {
        if let Some(found) = follower() {
            break found;
        }
        if Instant::now() >= until {
            cluster.saw("fault: a follower down past compaction, skipped: no leader and follower");
            return;
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    cluster.saw("fault: a follower down past compaction");
    cluster.stop(number);
    let until = Instant::now() + Duration::from_secs(60);
    loop {
        let compacted = cluster
            .leader(agent)
            .and_then(|leader| cluster.node(leader)?.replica(agent))
            .is_some_and(|status| status.log_start > last);
        if compacted {
            break;
        }
        if Instant::now() >= until {
            cluster.saw("fault: a follower down past compaction, a minute run out");
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    cluster.start(number);
}

/// [`FAULTS`] failures, one at a time: among them every clock jumping
/// past the skew under load, every session expiring, and a follower kept
/// down until the log compacts past it.
fn faults(cluster: &Cluster, clients: &[Client], random: &mut Random) {
    let pause = |random: &mut Random| {
        std::thread::sleep(Duration::from_millis(100 + random.below(400)));
    };
    let agents: Vec<AgentId> = clients
        .iter()
        .map(|client| client.agent)
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    for fault in 0..FAULTS {
        pause(random);
        if fault == FAULTS / 4 {
            // Batches timed before the jump refine after it, while their
            // callers, unanswered, send them again.
            cluster.saw("fault: every clock jumps past the skew");
            let held: Vec<_> = (1..=NODES)
                .map(|number| cluster.slot(number).trip.refines.close())
                .collect();
            cluster.offset.fetch_add(CLUSTER_JUMP, Ordering::SeqCst);
            std::thread::sleep(ATTEMPT + Duration::from_millis(500));
            drop(held);
            continue;
        }
        if fault == FAULTS / 2 {
            expire_every_session(cluster, clients, random);
            continue;
        }
        if fault == 3 * FAULTS / 4 {
            follower_down_past_compaction(
                cluster,
                agents[random.below(agents.len() as u64) as usize],
            );
            continue;
        }
        let agent = agents[random.below(agents.len() as u64) as usize];
        let any = 1 + random.below(u64::from(NODES)) as NodeNumber;
        match random.below(6) {
            0 => {
                cluster.saw("fault: stop");
                let number = cluster.leader(agent).unwrap_or(any);
                cluster.stop(number);
                pause(random);
                cluster.start(number);
            }
            1 => {
                // The window path: the leader applies, stops before it
                // answers, and its callers go to the next leader.
                let Some(number) = cluster.leader(agent) else {
                    continue;
                };
                let trip = &cluster.slot(number).trip;
                trip.tripped.store(false, Ordering::SeqCst);
                trip.armed.store(true, Ordering::SeqCst);
                let until = Instant::now() + Duration::from_secs(2);
                while !trip.tripped.load(Ordering::SeqCst) && Instant::now() < until {
                    std::thread::sleep(Duration::from_millis(1));
                }
                trip.armed.store(false, Ordering::SeqCst);
                cluster.saw(if trip.tripped.load(Ordering::SeqCst) {
                    "fault: stop between apply and answer"
                } else {
                    "fault: stop, nothing applied"
                });
                cluster.stop(number);
                pause(random);
                cluster.start(number);
            }
            5 => {
                // Clients calling the followers re-forward to the leader
                // they elect.
                cluster.saw("fault: the leader cut off");
                cluster.hub.isolate(cluster.leader(agent).unwrap_or(any));
                pause(random);
                pause(random);
                cluster.hub.heal();
            }
            2 => {
                cluster.saw("fault: isolate");
                cluster.hub.isolate(any);
                pause(random);
                cluster.hub.heal();
            }
            3 => {
                cluster.saw("fault: loss and delay");
                cluster.hub.set_loss(20_000);
                cluster
                    .hub
                    .set_delay(Duration::from_millis(1 + random.below(3)));
                pause(random);
                pause(random);
                cluster.hub.set_loss(0);
                cluster.hub.set_delay(Duration::ZERO);
            }
            _ => {
                // Ahead, then back: a leader that ran ahead leaves the
                // others trailing its time.
                cluster.saw("fault: clock jump");
                let jump = if random.below(2) == 0 {
                    NODE_JUMP
                } else {
                    -NODE_JUMP
                };
                let offset = &cluster.slot(any).offset;
                offset.store(jump, Ordering::SeqCst);
                pause(random);
                pause(random);
                offset.store(0, Ordering::SeqCst);
            }
        }
    }
}

/// Whether `node` holds any of `agent`'s session state.
fn holds_sessions(node: &Node, agent: AgentId) -> bool {
    let snapshot = node.store().snapshot();
    let any = Session {
        key: [0; 32],
        name: [0; 16],
        t0: 0,
    };
    let live = snapshot
        .get(agent, &keys::live_sessions())
        .unwrap()
        .map(|bytes| u64::decode(unstored(&bytes).unwrap()).unwrap().0);
    [
        keys::session_index(&any),
        keys::session_of(SessionId(0)),
        keys::session(SessionId(0)),
        keys::reply(SessionId(0), 0),
        keys::expiry_prefix(),
        keys::key_sessions(&[0; 32]),
    ]
    .iter()
    .any(|key| snapshot.scan(agent, &key[..2], None).next().is_some())
        || live.is_some_and(|live| live > 0)
}

/// A counter's value at `node`, on its applied state.
fn counted(node: &Node, agent: AgentId, instance: InstanceId, value: MethodId) -> Answer {
    match smol::block_on(node.query(
        agent,
        Principal::Client([0; 32]),
        instance,
        value,
        Vec::new(),
    )) {
        Ok(outcome) => Answer::Ran { outcome, at: 0 },
        Err(_) => Answer::Unavailable,
    }
}

/// Clients pause with every request answered, each keeping one it ran and
/// one signed but never sent; every clock moves past the expiry, and every
/// replica collects every session while a leader stops. Sent again to
/// every node, neither captured request runs, and every counter stays.
fn expire_every_session(cluster: &Cluster, clients: &[Client], random: &mut Random) {
    cluster.saw("fault: every session expires");
    cluster.paused.store(true, Ordering::SeqCst);
    wait_until("the clients pause", ANSWERED, || {
        clients.iter().all(Client::idle)
    });
    let captured: Vec<Vec<Vec<u8>>> = clients
        .iter()
        .map(|client| client.capture(cluster))
        .collect();
    cluster.offset.fetch_add(
        (defaults::SESSION_EXPIRY_MS + defaults::SESSION_BUCKET_MS + 60_000) as i64,
        Ordering::SeqCst,
    );
    let agent = clients[random.below(clients.len() as u64) as usize].agent;
    if let Some(leader) = cluster.leader(agent) {
        cluster.stop(leader);
        std::thread::sleep(Duration::from_millis(100 + random.below(400)));
        cluster.start(leader);
    }
    wait_until("every replica collects every session", ANSWERED, || {
        (1..=NODES).all(|number| {
            cluster.node(number).is_some_and(|node| {
                clients
                    .iter()
                    .all(|client| !holds_sessions(&node, client.agent))
            })
        })
    });
    for (client, captured) in clients.iter().zip(&captured) {
        client.replay(cluster, captured);
    }
    cluster.saw("captured requests refused");
    for client in clients {
        let total = client.total(client.sent());
        for number in 1..=NODES {
            let node = cluster.node(number).unwrap();
            wait_until("every counter as it was", ANSWERED, || {
                counted(&node, client.agent, client.instance, client.methods.value)
                    == Answer::Ran {
                        outcome: Outcome::Done(total.encode()),
                        at: 0,
                    }
            });
        }
    }
    cluster.paused.store(false, Ordering::SeqCst);
}

/// Ends the clients and readers when the faults are over, or have failed:
/// they stop pausing, and stop.
struct Ending<'a>(&'a AtomicBool, &'a Cluster);

impl Drop for Ending<'_> {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
        self.1.paused.store(false, Ordering::SeqCst);
    }
}

fn exactly_once(mode: Mode, default_seed: u64) {
    let seed = std::env::var("EXACTLY_ONCE_SEED")
        .ok()
        .and_then(|seed| seed.parse().ok())
        .unwrap_or(default_seed);
    println!("seed {seed}");
    let mut random = Random(seed | 1);
    let cluster = Cluster::new(seed);
    let counter = elf("test-actors/target/riscv64em-vos/release/counter.elf");
    let methods = Methods {
        increment: method(&counter, "increment"),
        value: method(&counter, "value"),
        forward: method(&counter, "forward"),
    };
    let value = methods.value;
    let agents: Vec<(AgentId, [u8; 32])> = (1..=3u8)
        .map(|number| {
            let creator = cluster.node(number).unwrap();
            let agent = creator.create_replicated(vec![1, 2, 3]).unwrap();
            wait_until("a leader", Duration::from_secs(20), || {
                cluster.leader(agent).is_some()
            });
            let leader = cluster.node(cluster.leader(agent).unwrap()).unwrap();
            // The inbox first: no message reaches an instance not there yet.
            for instance in [INBOX, COUNTER, SECOND] {
                let installed =
                    smol::block_on(leader.install(agent, instance, &counter, &[], vec![]));
                assert!(
                    matches!(installed, Ok(vos_node::Reply::Ran(Outcome::Done(_)))),
                    "{installed:?}"
                );
            }
            let target =
                Target::loopback(&format!("http://{}", cluster.slot(number).ingress)).unwrap();
            let record = vos_node::client::agent_info(&target, agent)
                .unwrap()
                .expect("the agent's record")
                .record;
            (agent, vos_node::identity(&record))
        })
        .collect();
    // At each agent, one client forwarding to the next agent's inbox and a
    // second incrementing a counter of its own: batches mix their
    // sessions, new and held.
    let clients: Vec<Client> = (1..=6u8)
        .map(|number| {
            let (agent, identity) = agents[usize::from(number - 1) % agents.len()];
            let forwarding = number <= 3;
            // The second clients start sessions often: first requests meet
            // every fault.
            let rotate = if forwarding {
                32 + 4 * random.below(8)
            } else {
                4 + 4 * random.below(2)
            };
            Client::new(number, agent, identity, methods, forwarding, rotate)
        })
        .collect();
    let forwarding = &clients[..agents.len()];
    for (at, client) in forwarding.iter().enumerate() {
        let next = &forwarding[(at + 1) % forwarding.len()];
        client.forward_to(next.agent);
    }
    let done = AtomicBool::new(false);
    let sent: Vec<u64> = std::thread::scope(|scope| {
        let running: Vec<_> = clients
            .iter()
            .map(|client| scope.spawn(|| client.run(&cluster, mode, &done)))
            .collect();
        for (at, client) in forwarding.iter().enumerate() {
            let previous = &forwarding[(at + forwarding.len() - 1) % forwarding.len()];
            let (cluster, done) = (&cluster, &done);
            scope.spawn(move || client.read(cluster, done, previous));
        }
        let ending = Ending(&done, &cluster);
        faults(&cluster, &clients, &mut random);
        drop(ending);
        running
            .into_iter()
            .map(|client| {
                client
                    .join()
                    .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
            })
            .collect()
    });
    println!("requests answered: {sent:?}");
    println!("{:?}", cluster.log.seen());
    assert!(
        cluster.log.seen().contains_key("session timed again"),
        "no session met the clocks' jump"
    );
    // Healed, every replica holds every request once.
    cluster.hub.heal();
    for number in 1..=NODES {
        if cluster.node(number).is_none() {
            cluster.start(number);
        }
    }
    let counted = |node: &Node, agent: AgentId, instance: InstanceId| match counted(
        node, agent, instance, value,
    ) {
        Answer::Ran { outcome, .. } => Ok(outcome),
        other => Err(other),
    };
    let mark = |node: &Node, agent: AgentId, key: &[u8]| {
        node.store()
            .snapshot()
            .get(agent, key)
            .unwrap()
            .map(|bytes| u64::decode(unstored(&bytes).unwrap()).unwrap().0)
            .unwrap_or(0)
    };
    for (at, client) in clients.iter().enumerate().skip(forwarding.len()) {
        let total = client.total(sent[at]);
        for number in 1..=NODES {
            let node = cluster.node(number).unwrap();
            wait_until("every replica converges", Duration::from_secs(60), || {
                counted(&node, client.agent, client.instance) == Ok(Outcome::Done(total.encode()))
            });
        }
    }
    for (at, client) in forwarding.iter().enumerate() {
        let sent = sent[at];
        let total = client.total(sent);
        let (next, next_agent) = (
            &forwarding[(at + 1) % forwarding.len()],
            client.next_agent().unwrap(),
        );
        let forwards = sent / 5;
        let inbox = client.forwarded(sent);
        for number in 1..=NODES {
            let node = cluster.node(number).unwrap();
            wait_until("every replica converges", Duration::from_secs(60), || {
                counted(&node, client.agent, COUNTER) == Ok(Outcome::Done(total.encode()))
                    && counted(&node, next_agent, INBOX) == Ok(Outcome::Done(inbox.encode()))
                    && mark(&node, client.agent, &keys::acked(next_agent)) == forwards
                    && node
                        .store()
                        .snapshot()
                        .scan(client.agent, &keys::outbox_prefix(), None)
                        .count()
                        == 0
            });
            // Each forward applied once at the receiver, and was sent once.
            assert_eq!(
                mark(&node, next.agent, &keys::pair_in(client.agent)),
                forwards
            );
            assert_eq!(
                mark(&node, client.agent, &keys::pair_out(next_agent)),
                forwards
            );
        }
    }
    let across: u64 = (1..=NODES)
        .map(|number| {
            cluster.slot(number).sent_across.load(Ordering::SeqCst)
                + cluster.node(number).unwrap().messages_sent_across()
        })
        .sum();
    println!("messages sent across nodes: {across}");
    let installed: u64 = (1..=NODES)
        .map(|number| {
            cluster.slot(number).installed.load(Ordering::SeqCst)
                + cluster.node(number).unwrap().snapshots_installed()
        })
        .sum();
    println!("snapshots installed: {installed}");
    assert!(installed > 0, "no node caught up by a snapshot");
    assert!(across > 0, "no message crossed nodes");
}

#[test]
fn one_request_at_a_time_applies_once_through_failures() {
    exactly_once(Mode::OneAtATime, 0x5eed_0001);
}

#[test]
fn pipelined_requests_apply_once_through_failures() {
    exactly_once(Mode::Pipelined, 0x5eed_0002);
}

/// The counter's total an answer carries.
fn done(answer: &Answer) -> Option<u64> {
    match answer {
        Answer::Ran {
            outcome: Outcome::Done(bytes),
            ..
        } => Some(u64::decode(bytes).unwrap().0),
        _ => None,
    }
}

/// A cluster with one agent replicated on `replicas`, running the
/// counter: the agent and its counter's methods.
fn counter_agent(cluster: &Cluster, replicas: Vec<NodeNumber>) -> (AgentId, MethodId, MethodId) {
    let counter = elf("test-actors/target/riscv64em-vos/release/counter.elf");
    let agent = cluster
        .node(replicas[0])
        .unwrap()
        .create_replicated(replicas)
        .unwrap();
    wait_until("a leader", Duration::from_secs(20), || {
        cluster.leader(agent).is_some()
    });
    let leader = cluster.node(cluster.leader(agent).unwrap()).unwrap();
    let installed = smol::block_on(leader.install(agent, COUNTER, &counter, &[], vec![]));
    assert!(
        matches!(installed, Ok(vos_node::Reply::Ran(Outcome::Done(_)))),
        "{installed:?}"
    );
    (
        agent,
        method(&counter, "increment"),
        method(&counter, "value"),
    )
}

fn target(cluster: &Cluster, number: NodeNumber) -> Target {
    Target::loopback(&format!("http://{}", cluster.slot(number).ingress)).unwrap()
}

/// The mark node `number` applied for `session` of `agent`.
fn mark(cluster: &Cluster, number: NodeNumber, agent: AgentId, session: &Session) -> u64 {
    let node = cluster.node(number).unwrap();
    let snapshot = node.store().snapshot();
    let value = |key: &[u8]| {
        snapshot
            .get(agent, key)
            .unwrap()
            .map(|bytes| unstored(&bytes).unwrap().to_vec())
    };
    let Some(id) = value(&keys::session_index(session)) else {
        return 0;
    };
    let id = SessionId::decode(&id).unwrap().0;
    SessionMark::decode(&value(&keys::session(id)).unwrap())
        .unwrap()
        .0
        .sequence
}

/// A follower forwards a call to the leader, and answers it once it has
/// applied it itself; the client goes on calling the follower.
#[test]
fn a_follower_forwards_a_call_and_answers_once_it_applied_it() {
    let cluster = Cluster::new(1);
    let (agent, increment, _) = counter_agent(&cluster, vec![1, 2, 3]);
    let leader = cluster.leader(agent).unwrap();
    let follower = leader % NODES + 1;
    let mut client = vos_node::client::Client::new(
        &target(&cluster, follower),
        SigningKey::from_bytes(&[7; 32]),
    );
    for (sequence, (by, total)) in [(5u64, 5u64), (2, 7)].into_iter().enumerate() {
        let answer = client
            .call(agent, COUNTER, increment, &by.encode())
            .unwrap();
        assert_eq!(done(&answer), Some(total), "{answer:?}");
        let session = client.session(agent);
        assert!(
            mark(&cluster, follower, agent, &session) > sequence as u64,
            "answered before the follower applied it"
        );
    }
    assert_eq!(
        vos_node::client::node_id(client.target()).unwrap().0,
        cluster.space.node(follower).unwrap().key,
        "the client still calls the follower"
    );
}

/// A follower checks a call's signature before it forwards the call: the
/// leader runs forwarded calls without checking them again.
#[test]
fn a_follower_forwards_no_call_it_cannot_verify() {
    let cluster = Cluster::new(3);
    let (agent, increment, value) = counter_agent(&cluster, vec![1, 2, 3]);
    let leader = cluster.leader(agent).unwrap();
    let follower = leader % NODES + 1;
    let at = target(&cluster, follower);
    let client = vos_node::client::Client::new(&at, SigningKey::from_bytes(&[9; 32]));
    let body = client
        .call_body(agent, 1, COUNTER, increment, &5u64.encode())
        .unwrap();
    let mut call = Call::decode(&body).unwrap().0;
    call.arguments = 6u64.encode();
    let path = format!("/agents/{}/calls", agent.0);
    assert_eq!(
        post(cluster.slot(follower).ingress, &path, &call.encode()),
        Ok(Answer::Rejected(Rejection::BadSignature))
    );
    std::thread::sleep(Duration::from_millis(200));
    let node = cluster.node(leader).unwrap();
    let total = smol::block_on(node.query(
        agent,
        Principal::Client([0; 32]),
        COUNTER,
        value,
        Vec::new(),
    ));
    assert_eq!(total, Ok(Outcome::Done(0u64.encode())), "it never ran");
}

/// A node that does not replicate the agent names its replicas, and the
/// client calls one of them from then on.
#[test]
fn a_client_follows_elsewhere_to_a_replica() {
    let cluster = Cluster::new(4);
    let (agent, increment, _) = counter_agent(&cluster, vec![1, 2]);
    let mut client =
        vos_node::client::Client::new(&target(&cluster, 3), SigningKey::from_bytes(&[10; 32]));
    let answer = client
        .call(agent, COUNTER, increment, &4u64.encode())
        .unwrap();
    assert_eq!(done(&answer), Some(4), "{answer:?}");
    let now = vos_node::client::node_id(client.target()).unwrap().0;
    assert!(
        [1, 2]
            .iter()
            .any(|number| cluster.space.node(*number).unwrap().key == now),
        "the client calls a replica now"
    );
}

/// A leader whose clock trails the agent's time, as one does after a
/// leader with a clock ahead, times its batches at the agent's time and
/// goes on leading: the agent's time never goes back.
#[test]
fn a_leader_whose_clock_trails_times_its_batches_at_the_agents() {
    let cluster = Cluster::new(2);
    let (agent, increment, _) = counter_agent(&cluster, vec![1, 2, 3]);
    let leader = cluster.leader(agent).unwrap();
    let mut client =
        vos_node::client::Client::new(&target(&cluster, leader), SigningKey::from_bytes(&[8; 32]));
    let batch_time = || {
        let node = cluster.node(leader).unwrap();
        let bytes = node
            .store()
            .snapshot()
            .get(agent, &keys::batch_time())
            .unwrap()
            .unwrap();
        u64::decode(unstored(&bytes).unwrap()).unwrap().0
    };
    let offset = &cluster.slot(leader).offset;
    offset.store(30_000, Ordering::SeqCst);
    let answer = client
        .call(agent, COUNTER, increment, &1u64.encode())
        .unwrap();
    assert_eq!(done(&answer), Some(1), "{answer:?}");
    let ahead = batch_time();
    assert!(
        ahead >= vos_node::wall_clock() + 20_000,
        "timed by the clock ahead"
    );
    // The clock comes back: it trails the agent's time by more than the
    // bound.
    offset.store(0, Ordering::SeqCst);
    let answer = client
        .call(agent, COUNTER, increment, &2u64.encode())
        .unwrap();
    assert_eq!(done(&answer), Some(3), "{answer:?}");
    assert_eq!(cluster.leader(agent), Some(leader), "it goes on leading");
    assert!(batch_time() >= ahead, "the agent's time went back");
}

/// A signed call: `by` added in `session`, at `sequence`.
fn signed_call(
    identity: &[u8; 32],
    key: &SigningKey,
    session: Session,
    sequence: u64,
    increment: MethodId,
    by: u64,
) -> Vec<u8> {
    let arguments = by.encode();
    let message = call_message(identity, &session, sequence, COUNTER, increment, &arguments);
    Call {
        session,
        sequence,
        instance: COUNTER,
        method: increment,
        arguments,
        signature: key.sign(&message).to_bytes(),
    }
    .encode()
}

/// A resend of a new session's first call, while the first is queued,
/// joins it even once the session's time is past the skew: the first was
/// timed when its batch formed, and refusing the resend `StaleSession`
/// would have the client run it again in a new session.
#[test]
fn a_resend_of_a_queued_first_call_joins_it_past_the_skew() {
    let cluster = Cluster::new(5);
    let (agent, increment, value) = counter_agent(&cluster, vec![1, 2, 3]);
    let leader = cluster.leader(agent).unwrap();
    let identity = vos_node::identity(
        &vos_node::client::agent_info(&target(&cluster, leader), agent)
            .unwrap()
            .unwrap()
            .record,
    );
    let key = SigningKey::from_bytes(&[11; 32]);
    let session = Session {
        key: key.verifying_key().to_bytes(),
        name: [11; 16],
        t0: vos_node::wall_clock() - (vos_wire::defaults::SESSION_SKEW_MS - 1_500),
    };
    let body = signed_call(&identity, &key, session, 1, increment, 5);
    let path = format!("/agents/{}/calls", agent.0);
    let address = cluster.slot(leader).ingress;
    let refines = &cluster.slot(leader).trip.refines;
    let reached = refines.reached.load(Ordering::SeqCst);
    std::thread::scope(|scope| {
        // Inside the scope: a failure opens it before the scope waits.
        let closed = refines.close();
        let first = scope.spawn(|| post_within(address, &path, &body, ANSWERED));
        wait_until("the first is refined", Duration::from_secs(10), || {
            refines.reached.load(Ordering::SeqCst) > reached
        });
        // Past the skew now.
        std::thread::sleep(Duration::from_millis(2_000));
        let second = scope.spawn(|| post_within(address, &path, &body, ANSWERED));
        std::thread::sleep(Duration::from_millis(300));
        drop(closed);
        for answer in [first.join().unwrap(), second.join().unwrap()] {
            let answer = answer.unwrap();
            assert_eq!(done(&answer), Some(5), "{answer:?}");
        }
    });
    let node = cluster.node(leader).unwrap();
    let total = smol::block_on(node.query(
        agent,
        Principal::Client([0; 32]),
        COUNTER,
        value,
        Vec::new(),
    ));
    assert_eq!(total, Ok(Outcome::Done(5u64.encode())), "ran once");
}

/// A follower answers a forwarded call only once it has applied it: while
/// its commits are held, the leader has run the call and the client waits.
#[test]
fn a_follower_holding_back_its_apply_holds_back_its_answer() {
    let cluster = Cluster::new(6);
    let (agent, increment, value) = counter_agent(&cluster, vec![1, 2, 3]);
    let leader = cluster.leader(agent).unwrap();
    let follower = leader % NODES + 1;
    let mut client = vos_node::client::Client::new(
        &target(&cluster, follower),
        SigningKey::from_bytes(&[12; 32]),
    );
    client.identity(agent).unwrap();
    let commits = &cluster.slot(follower).trip.commits;
    std::thread::scope(|scope| {
        let closed = commits.close();
        let (answered, answer) = std::sync::mpsc::channel();
        scope.spawn(move || {
            let _ = answered.send(client.call(agent, COUNTER, increment, &3u64.encode()));
        });
        let node = cluster.node(leader).unwrap();
        wait_until("the leader runs it", Duration::from_secs(10), || {
            smol::block_on(node.query(
                agent,
                Principal::Client([0; 32]),
                COUNTER,
                value,
                Vec::new(),
            )) == Ok(Outcome::Done(3u64.encode()))
        });
        std::thread::sleep(Duration::from_millis(300));
        let early = answer.try_recv();
        drop(closed);
        assert!(early.is_err(), "answered before the follower applied it");
        let answer = answer.recv().unwrap().unwrap();
        assert_eq!(done(&answer), Some(3), "{answer:?}");
    });
}

/// A signed query of the counter's value, by `key`.
fn value_query(
    identity: &[u8; 32],
    key: &SigningKey,
    value: MethodId,
    consistency: Consistency,
) -> Vec<u8> {
    let not_after = vos_node::wall_clock() + 60_000;
    let public = key.verifying_key().to_bytes();
    let message = query_message(
        identity,
        &public,
        not_after,
        consistency,
        COUNTER,
        value,
        &[],
    );
    QueryCall {
        key: public,
        not_after,
        consistency,
        instance: COUNTER,
        method: value,
        arguments: Vec::new(),
        signature: key.sign(&message).to_bytes(),
    }
    .encode()
}

/// A follower reads a write it has not applied yet only once it has: at
/// the floor the write's answer gave, and by read index.
#[test]
fn a_follower_reads_a_write_once_it_has_applied_it() {
    let cluster = Cluster::new(7);
    let (agent, increment, value) = counter_agent(&cluster, vec![1, 2, 3]);
    let leader = cluster.leader(agent).unwrap();
    let follower = leader % NODES + 1;
    let identity = vos_node::identity(
        &vos_node::client::agent_info(&target(&cluster, leader), agent)
            .unwrap()
            .unwrap()
            .record,
    );
    let key = SigningKey::from_bytes(&[13; 32]);
    let path = format!("/agents/{}/queries", agent.0);
    let commits = &cluster.slot(follower).trip.commits;
    let session = Session {
        key: key.verifying_key().to_bytes(),
        name: [13; 16],
        t0: vos_node::wall_clock(),
    };
    for (sequence, consistency) in [(1, None), (2, Some(Consistency::Linearizable))] {
        std::thread::scope(|scope| {
            let closed = commits.close();
            let call = signed_call(&identity, &key, session, sequence, increment, 4);
            let calls = format!("/agents/{}/calls", agent.0);
            let answer =
                post_within(cluster.slot(leader).ingress, &calls, &call, ANSWERED).unwrap();
            let Answer::Ran { at, .. } = answer else {
                panic!("{answer:?}")
            };
            let consistency = consistency.unwrap_or(Consistency::Applied { at });
            let query = value_query(&identity, &key, value, consistency);
            let (answered, read) = std::sync::mpsc::channel();
            let (path, address) = (&path, cluster.slot(follower).ingress);
            scope.spawn(move || {
                let _ = answered.send(post_within(address, path, &query, ANSWERED));
            });
            std::thread::sleep(Duration::from_millis(300));
            let early = read.try_recv();
            drop(closed);
            assert!(
                early.is_err(),
                "read before the follower applied it: {early:?}"
            );
            let answer = read.recv().unwrap().unwrap();
            assert_eq!(
                done(&answer),
                Some(4 * sequence),
                "{consistency:?}: {answer:?}"
            );
        });
    }
}

/// A leader cut off from its followers answers no linearizable read: it
/// cannot confirm it still leads.
#[test]
fn a_leader_cut_off_answers_no_linearizable_read() {
    let cluster = Cluster::new(8);
    let (agent, _, value) = counter_agent(&cluster, vec![1, 2, 3]);
    let leader = cluster.leader(agent).unwrap();
    let identity = vos_node::identity(
        &vos_node::client::agent_info(&target(&cluster, leader), agent)
            .unwrap()
            .unwrap()
            .record,
    );
    let key = SigningKey::from_bytes(&[14; 32]);
    let path = format!("/agents/{}/queries", agent.0);
    cluster.hub.isolate(leader);
    let answer = post_within(
        cluster.slot(leader).ingress,
        &path,
        &value_query(&identity, &key, value, Consistency::Linearizable),
        ANSWERED,
    );
    cluster.hub.heal();
    assert!(
        !matches!(answer, Ok(Answer::Ran { .. })),
        "a cut-off leader answered: {answer:?}"
    );
}

/// A replica that has not applied through a query's floor in time answers
/// `Behind`, and the client's query goes on to another replica.
#[test]
fn a_query_a_replica_is_behind_for_goes_to_another() {
    let cluster = Cluster::new(9);
    let (agent, increment, value) = counter_agent(&cluster, vec![1, 2, 3]);
    let leader = cluster.leader(agent).unwrap();
    let follower = leader % NODES + 1;
    let key = SigningKey::from_bytes(&[15; 32]);
    let mut client = vos_node::client::Client::new(&target(&cluster, leader), key.clone());
    let identity = client.identity(agent).unwrap();
    let commits = &cluster.slot(follower).trip.commits;
    std::thread::scope(|_| {
        let _closed = commits.close();
        let answer = client
            .call(agent, COUNTER, increment, &6u64.encode())
            .unwrap();
        let Answer::Ran { at, .. } = answer else {
            panic!("{answer:?}")
        };
        let path = format!("/agents/{}/queries", agent.0);
        let query = value_query(&identity, &key, value, Consistency::Applied { at });
        assert_eq!(
            post_within(cluster.slot(follower).ingress, &path, &query, ANSWERED),
            Ok(Answer::Rejected(Rejection::Behind))
        );
        let reader = vos_node::client::Client::new(&target(&cluster, follower), key.clone());
        reader.raise_floor(agent, at);
        let answer = reader
            .query(agent, COUNTER, value, &[], vos_node::wall_clock() + 60_000)
            .unwrap();
        assert_eq!(done(&answer), Some(6), "{answer:?}");
    });
}
