//! Exactly once, over HTTP, through failures: clients increment counters
//! on three nodes, each request resent with its sequence until answered,
//! in sessions they start every few dozen requests, while the nodes stop
//! and start, a leader stops between its apply and its answer, a node is
//! cut off, the network loses and delays frames, and a node's clock jumps.
//!
//! Every answer must be its session's running total: no request applied
//! twice, none skipped. A node must hold a request applied before it
//! answers it, and at the end every replica holds every request once.
//!
//! The seed is printed; `EXACTLY_ONCE_SEED` runs one again.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use vos_net::memory::Hub;
use vos_node::client::Target;
use vos_node::store::{Store, View};
use vos_node::{Config, Hooks, Node, Peers, Space, SpaceNode};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, Session, SessionId};
use vos_wire::ingress::{Answer, Call, Rejection, call_message};
use vos_wire::peer::NodeNumber;
use vos_wire::records::{SessionMark, unstored};
use vos_wire::result::Outcome;
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode, keys};

const COUNTER: InstanceId = InstanceId(1);
const NODES: NodeNumber = 3;
/// How long one attempt waits for its answer before trying another node.
const ATTEMPT: Duration = Duration::from_secs(2);
/// How long a request may take to be answered, through every failure.
const ANSWERED: Duration = Duration::from_secs(60);
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

fn wait_until(what: &str, within: Duration, mut done: impl FnMut() -> bool) {
    let until = Instant::now() + within;
    while !done() {
        assert!(Instant::now() < until, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// A small seeded generator, so a failing run can be run again.
struct Random(u64);

impl Random {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }

    fn below(&mut self, bound: u64) -> u64 {
        self.next() % bound
    }
}

/// Stops a leader loop once, after its commit and before its answers.
#[derive(Default)]
struct Trip {
    armed: AtomicBool,
    tripped: AtomicBool,
}

impl Hooks for Trip {
    fn after_commit(&self, _: AgentId, _: u64) -> bool {
        if self.armed.swap(false, Ordering::SeqCst) {
            self.tripped.store(true, Ordering::SeqCst);
            return false;
        }
        true
    }
}

/// One node's slot: its node while it runs, how often it started, its
/// hook and its clock's offset.
struct Slot {
    node: Mutex<Option<Arc<Node>>>,
    starts: AtomicU64,
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
    /// What happened, by name: printed, so a run shows what it tried.
    seen: Mutex<std::collections::BTreeMap<&'static str, u64>>,
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
            let free = || {
                TcpListener::bind("127.0.0.1:0")
                    .unwrap()
                    .local_addr()
                    .unwrap()
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
                trip: Arc::new(Trip::default()),
                offset: Arc::new(AtomicI64::new(0)),
                dir,
                ingress,
            });
        }
        let cluster = Self {
            hub: Hub::new(seed),
            space: Space::new(nodes).unwrap(),
            agent,
            slots,
            seen: Mutex::new(std::collections::BTreeMap::new()),
        };
        for number in 1..=NODES {
            cluster.start(number);
        }
        cluster
    }

    fn saw(&self, what: &'static str) {
        *self.seen.lock().unwrap().entry(what).or_default() += 1;
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
        let offset = Arc::clone(&slot.offset);
        config.clock = Arc::new(move || {
            vos_node::wall_clock().saturating_add_signed(offset.load(Ordering::SeqCst))
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
        node.shutdown();
    }

    fn node(&self, number: NodeNumber) -> Option<Arc<Node>> {
        self.slot(number).node.lock().unwrap().clone()
    }

    /// The running node leading `agent`, if one does.
    fn leader(&self, agent: AgentId) -> Option<NodeNumber> {
        (1..=NODES).find(|number| self.node(*number).is_some_and(|node| node.leads(agent)))
    }

    fn number_at(&self, address: &str) -> Option<NodeNumber> {
        self.space
            .nodes()
            .iter()
            .find(|node| node.ingress == address)
            .map(|node| node.number)
    }
}

/// POST `body` at `address`, answered within [`ATTEMPT`].
fn post(address: SocketAddr, path: &str, body: &[u8]) -> Result<Answer, String> {
    let failed = |error: std::io::Error| error.to_string();
    let mut stream = TcpStream::connect_timeout(&address, ATTEMPT).map_err(failed)?;
    stream.set_read_timeout(Some(ATTEMPT)).map_err(failed)?;
    stream.set_write_timeout(Some(ATTEMPT)).map_err(failed)?;
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

/// How a client sends its requests.
#[derive(Clone, Copy)]
enum Mode {
    /// One request in flight at a time.
    OneAtATime,
    /// Several in flight, each on its connection: lanes, in-flight
    /// duplicates and gaps meet the failures.
    Pipelined,
}

/// One client at its own agent, whose counter only it increments, so each
/// answer is the running total of its amounts. It starts a new session
/// every so many requests, so new sessions meet the failures too.
struct Client {
    number: u8,
    agent: AgentId,
    key: SigningKey,
    identity: [u8; 32],
    increment: MethodId,
    /// Requests in each session: a multiple of four, so a pipelined window
    /// stays in one.
    rotate: u64,
    /// Its sessions, each started when the client reaches it.
    sessions: Mutex<Vec<Session>>,
    /// The node it believes leads.
    guess: Mutex<NodeNumber>,
}

impl Client {
    fn amount(&self, request: u64) -> u64 {
        request * 1000 + u64::from(self.number)
    }

    fn total(&self, request: u64) -> u64 {
        (1..=request).map(|request| self.amount(request)).sum()
    }

    /// The session request number `request` goes in, and its sequence
    /// there.
    fn session(&self, cluster: &Cluster, request: u64) -> (Session, u64) {
        let index = (request - 1) / self.rotate;
        let mut sessions = self.sessions.lock().unwrap();
        while sessions.len() as u64 <= index {
            let mut name = [0u8; 16];
            name[0] = self.number;
            name[8..].copy_from_slice(&(sessions.len() as u64).to_be_bytes());
            sessions.push(Session {
                key: self.key.verifying_key().to_bytes(),
                name,
                t0: vos_node::wall_clock(),
            });
            cluster.saw("session started");
        }
        (sessions[index as usize], request - index * self.rotate)
    }

    fn body(&self, session: &Session, sequence: u64, request: u64) -> Vec<u8> {
        let arguments = self.amount(request).encode();
        let message = call_message(
            &self.identity,
            session,
            sequence,
            COUNTER,
            self.increment,
            &arguments,
        );
        Call {
            session: *session,
            sequence,
            instance: COUNTER,
            method: self.increment,
            arguments,
            signature: self.key.sign(&message).to_bytes(),
        }
        .encode()
    }

    /// Send request `request` until it is answered, following redirects
    /// and moving on from a node that fails; check its answer.
    fn send(&self, cluster: &Cluster, mode: Mode, request: u64) {
        let (session, sequence) = self.session(cluster, request);
        let body = self.body(&session, sequence, request);
        let path = format!("/agents/{}/calls", self.agent.0);
        let until = Instant::now() + ANSWERED;
        loop {
            assert!(
                Instant::now() < until,
                "client {}: request {request} was never answered",
                self.number
            );
            let at = *self.guess.lock().unwrap();
            let starts = cluster.slot(at).starts.load(Ordering::SeqCst);
            let next = |client: &Self| {
                *client.guess.lock().unwrap() = at % NODES + 1;
            };
            match post(cluster.slot(at).ingress, &path, &body) {
                Ok(Answer::Ran(Outcome::Done(reply))) => {
                    let total = u64::decode(&reply).unwrap().0;
                    assert_eq!(
                        total,
                        self.total(request),
                        "client {}: request {request} answered by node {at}",
                        self.number
                    );
                    self.applied_at(cluster, at, starts, &session, sequence);
                    return;
                }
                Ok(Answer::NotLeader {
                    leader: Some(leader),
                }) => {
                    cluster.saw("redirect");
                    match cluster.number_at(&leader.address) {
                        Some(leader) => *self.guess.lock().unwrap() = leader,
                        None => panic!("a redirect to {}", leader.address),
                    }
                }
                Ok(Answer::NotLeader { leader: None }) | Ok(Answer::Stopped) | Err(_) => {
                    cluster.saw("resend elsewhere");
                    next(self);
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(Answer::Busy | Answer::Unavailable) => {
                    cluster.saw("resend");
                    std::thread::sleep(Duration::from_millis(10));
                }
                // Sent on its own connection, a request may pass its
                // predecessor: it goes again once that one is in.
                Ok(Answer::Rejected(Rejection::Gap { expected }))
                    if matches!(mode, Mode::Pipelined) && expected < sequence =>
                {
                    cluster.saw("gap");
                    std::thread::sleep(Duration::from_millis(5));
                }
                Ok(other) => panic!(
                    "client {}: request {request} (sequence {sequence}) at node {at}: {other:?}",
                    self.number
                ),
            }
        }
    }

    /// After node `at` answered `sequence` of `session`, its applied state
    /// holds it, unless it restarted since.
    fn applied_at(
        &self,
        cluster: &Cluster,
        at: NodeNumber,
        starts: u64,
        session: &Session,
        sequence: u64,
    ) {
        let Some(node) = cluster.node(at) else {
            return;
        };
        if cluster.slot(at).starts.load(Ordering::SeqCst) != starts {
            return;
        }
        let snapshot = node.store().snapshot();
        let value = |key: &[u8]| {
            snapshot
                .get(self.agent, key)
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

    /// Send requests until `done`: how many were answered.
    fn run(&self, cluster: &Cluster, mode: Mode, done: &AtomicBool) -> u64 {
        let mut sent = 0;
        while !done.load(Ordering::SeqCst) {
            match mode {
                Mode::OneAtATime => {
                    sent += 1;
                    self.send(cluster, mode, sent);
                }
                Mode::Pipelined => {
                    std::thread::scope(|scope| {
                        for sequence in sent + 1..=sent + 4 {
                            scope.spawn(move || self.send(cluster, mode, sequence));
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    });
                    sent += 4;
                }
            }
        }
        sent
    }
}

/// [`FAULTS`] failures, one at a time.
fn faults(cluster: &Cluster, agents: &[AgentId], random: &mut Random) {
    let pause = |random: &mut Random| {
        std::thread::sleep(Duration::from_millis(100 + random.below(400)));
    };
    for _ in 0..FAULTS {
        pause(random);
        let agent = agents[random.below(agents.len() as u64) as usize];
        let any = 1 + random.below(u64::from(NODES)) as NodeNumber;
        match random.below(5) {
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
                    15_000
                } else {
                    -15_000
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

fn exactly_once(mode: Mode, default_seed: u64) {
    let seed = std::env::var("EXACTLY_ONCE_SEED")
        .ok()
        .and_then(|seed| seed.parse().ok())
        .unwrap_or(default_seed);
    println!("seed {seed}");
    let mut random = Random(seed | 1);
    let cluster = Cluster::new(seed);
    let counter = elf("test-actors/target/riscv64em-vos/release/counter.elf");
    let increment = method(&counter, "increment");
    let value = method(&counter, "value");
    let clients: Vec<Client> = (1..=3u8)
        .map(|number| {
            let creator = cluster.node(number).unwrap();
            let agent = creator.create_replicated(vec![1, 2, 3]).unwrap();
            wait_until("a leader", Duration::from_secs(20), || {
                cluster.leader(agent).is_some()
            });
            let leader = cluster.node(cluster.leader(agent).unwrap()).unwrap();
            let installed = smol::block_on(leader.install(agent, COUNTER, &counter, &[], vec![]));
            assert!(
                matches!(installed, Ok(vos_node::Reply::Ran(Outcome::Done(_)))),
                "{installed:?}"
            );
            let target =
                Target::loopback(&format!("http://{}", cluster.slot(number).ingress)).unwrap();
            let record = vos_node::client::record(&target, agent)
                .unwrap()
                .expect("the agent's record");
            Client {
                number,
                agent,
                key: SigningKey::from_bytes(&[number; 32]),
                identity: vos_node::identity(&record),
                increment,
                rotate: 32 + 4 * random.below(8),
                sessions: Mutex::new(Vec::new()),
                guess: Mutex::new(number),
            }
        })
        .collect();
    let agents: Vec<AgentId> = clients.iter().map(|client| client.agent).collect();
    let done = AtomicBool::new(false);
    let sent: Vec<u64> = std::thread::scope(|scope| {
        let running: Vec<_> = clients
            .iter()
            .map(|client| scope.spawn(|| client.run(&cluster, mode, &done)))
            .collect();
        faults(&cluster, &agents, &mut random);
        done.store(true, Ordering::SeqCst);
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
    println!("{:?}", cluster.seen.lock().unwrap());
    // Healed, every replica holds every request once.
    cluster.hub.heal();
    for number in 1..=NODES {
        if cluster.node(number).is_none() {
            cluster.start(number);
        }
    }
    for (client, sent) in clients.iter().zip(sent) {
        let total = client.total(sent);
        for number in 1..=NODES {
            let node = cluster.node(number).unwrap();
            wait_until("every replica converges", Duration::from_secs(20), || {
                let outcome = smol::block_on(node.query(
                    client.agent,
                    Principal::Client([0; 32]),
                    COUNTER,
                    value,
                    Vec::new(),
                ));
                outcome == Ok(Outcome::Done(total.encode()))
            });
        }
    }
}

#[test]
fn one_request_at_a_time_applies_once_through_failures() {
    exactly_once(Mode::OneAtATime, 0x5eed_0001);
}

#[test]
fn pipelined_requests_apply_once_through_failures() {
    exactly_once(Mode::Pipelined, 0x5eed_0002);
}

/// A cluster with one agent running the counter: the agent and its
/// counter's methods.
fn counter_agent(cluster: &Cluster) -> (AgentId, MethodId, MethodId) {
    let counter = elf("test-actors/target/riscv64em-vos/release/counter.elf");
    let agent = cluster
        .node(1)
        .unwrap()
        .create_replicated(vec![1, 2, 3])
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

/// A client sent to a follower goes on to the leader the follower names,
/// and calls it from then on.
#[test]
fn a_client_follows_a_redirect_to_the_leader() {
    let cluster = Cluster::new(1);
    let (agent, increment, _) = counter_agent(&cluster);
    let leader = cluster.leader(agent).unwrap();
    let follower = leader % NODES + 1;
    let mut client = vos_node::client::Client::new(
        &target(&cluster, follower),
        SigningKey::from_bytes(&[7; 32]),
    );
    for (by, total) in [(5u64, 5u64), (2, 7)] {
        assert_eq!(
            client
                .call(agent, COUNTER, increment, &by.encode())
                .unwrap(),
            Answer::Ran(Outcome::Done(total.encode()))
        );
    }
    let at = |target: &Target| vos_node::client::node_id(target).unwrap().0;
    assert_eq!(
        at(client.target()),
        cluster.space.node(leader).unwrap().key,
        "the client calls the leader now"
    );
}

/// A leader whose clock trails the agent's time, as one does after a
/// leader with a clock ahead, times its batches at the agent's time and
/// goes on leading: the agent's time never goes back.
#[test]
fn a_leader_whose_clock_trails_times_its_batches_at_the_agents() {
    let cluster = Cluster::new(2);
    let (agent, increment, _) = counter_agent(&cluster);
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
    assert_eq!(
        client
            .call(agent, COUNTER, increment, &1u64.encode())
            .unwrap(),
        Answer::Ran(Outcome::Done(1u64.encode()))
    );
    let ahead = batch_time();
    assert!(
        ahead >= vos_node::wall_clock() + 20_000,
        "timed by the clock ahead"
    );
    // The clock comes back: it trails the agent's time by more than the
    // bound.
    offset.store(0, Ordering::SeqCst);
    assert_eq!(
        client
            .call(agent, COUNTER, increment, &2u64.encode())
            .unwrap(),
        Answer::Ran(Outcome::Done(3u64.encode()))
    );
    assert_eq!(cluster.leader(agent), Some(leader), "it goes on leading");
    assert!(batch_time() >= ahead, "the agent's time went back");
}
