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
use vos_wire::abi::refusal;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Principal, Session, SessionId};
use vos_wire::ingress::{
    Answer, Call, Consistency, QueryCall, Rejection, call_message, query_message,
};
use vos_wire::peer::NodeNumber;
use vos_wire::records::{SessionMark, unstored};
use vos_wire::result::Outcome;
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode, defaults, keys};

const COUNTER: InstanceId = InstanceId(1);
/// The counter instance an agent's messages increment.
const INBOX: InstanceId = InstanceId(2);
/// The counter instance a second client at each agent increments.
const SECOND: InstanceId = InstanceId(3);
/// How far one node's clock jumps, either way.
const NODE_JUMP: i64 = 15_000;
/// How far every clock jumps ahead, once a run: past the skew and both
/// ways of a node's jump, with 30 s to spare.
const CLUSTER_JUMP: i64 = 120_000;
const _: () = assert!(CLUSTER_JUMP >= defaults::SESSION_SKEW_MS as i64 + 2 * NODE_JUMP + 30_000);
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
    /// The latest events, for a failure to show what led to it.
    events: Mutex<std::collections::VecDeque<String>>,
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
            events: Mutex::new(std::collections::VecDeque::new()),
            offset: Arc::new(AtomicI64::new(0)),
            paused: AtomicBool::new(false),
        };
        for number in 1..=NODES {
            cluster.start(number);
        }
        cluster
    }

    fn saw(&self, what: &'static str) {
        *self.seen.lock().unwrap().entry(what).or_default() += 1;
        if what.starts_with("fault") {
            self.event(format!(
                "{what}, leaders {:?}",
                self.slots
                    .iter()
                    .map(|slot| slot.node.lock().unwrap().is_some())
                    .collect::<Vec<_>>()
            ));
        }
    }

    fn event(&self, what: String) {
        let mut events = self.events.lock().unwrap();
        if events.len() == 40 {
            events.pop_front();
        }
        events.push_back(what);
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
        node.shutdown();
    }

    fn node(&self, number: NodeNumber) -> Option<Arc<Node>> {
        self.slot(number).node.lock().unwrap().clone()
    }

    /// The running node leading `agent`, if one does.
    fn leader(&self, agent: AgentId) -> Option<NodeNumber> {
        (1..=NODES).find(|number| self.node(*number).is_some_and(|node| node.leads(agent)))
    }

    /// The cluster's clock offset.
    fn offset(&self) -> i64 {
        self.offset.load(Ordering::SeqCst)
    }

    /// The cluster's time, as clients take it.
    fn time(&self) -> u64 {
        vos_node::wall_clock().saturating_add_signed(self.offset())
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

/// How a client sends its requests.
#[derive(Clone, Copy)]
enum Mode {
    /// One request in flight at a time.
    OneAtATime,
    /// Several in flight, each on its connection: lanes, in-flight
    /// duplicates and gaps meet the failures.
    Pipelined,
}

/// One client at an agent, whose counter instance only it increments, so
/// each answer is the running total of its amounts. It starts a new
/// session every so many requests, so new sessions meet the failures too.
struct Client {
    number: u8,
    agent: AgentId,
    key: SigningKey,
    identity: [u8; 32],
    increment: MethodId,
    /// The counter it increments.
    instance: InstanceId,
    /// Whether every fifth request forwards to the next agent's inbox.
    forwarding: bool,
    /// Requests in each session: a multiple of four, so a pipelined window
    /// stays in one.
    rotate: u64,
    /// Its sessions, each started when the client reaches it, in order.
    sessions: Mutex<Vec<Timed>>,
    /// Sessions named so far.
    names: AtomicU64,
    /// It stopped for a pause.
    idle: AtomicBool,
    /// The node it calls, until it fails.
    calling: Mutex<NodeNumber>,
    value: MethodId,
    forward: MethodId,
    /// The next client's agent, which its forwards go to.
    next: std::sync::OnceLock<AgentId>,
    /// The highest request it has started to send.
    sent: AtomicU64,
    /// The requests answered: through a prefix, and those above it.
    acked: Mutex<Acked>,
}

/// A session from its first request on, timed with the cluster's clock
/// offset when it started, and the secret of its key.
#[derive(Clone, Copy)]
struct Timed {
    first: u64,
    session: Session,
    offset: i64,
    secret: [u8; 32],
}

/// The requests a client has had answered.
#[derive(Default)]
struct Acked {
    /// Every request through this one was answered...
    prefix: u64,
    /// ... the last of them at this applied index...
    at: u64,
    /// ... and these above it, with theirs.
    above: std::collections::BTreeMap<u64, u64>,
}

impl Acked {
    fn answered(&mut self, request: u64, at: u64) {
        self.above.insert(request, at);
        while let Some(at) = self.above.remove(&(self.prefix + 1)) {
            self.prefix += 1;
            self.at = at;
        }
    }
}

impl Client {
    fn amount(&self, request: u64) -> u64 {
        request * 1000 + u64::from(self.number)
    }

    /// Whether request `request` forwards its amount to the next agent's
    /// inbox, rather than incrementing this client's counter.
    fn forwards(&self, request: u64) -> bool {
        self.forwarding && request.is_multiple_of(5)
    }

    /// The counter after requests 1 through `request`.
    fn total(&self, request: u64) -> u64 {
        (1..=request)
            .filter(|request| !self.forwards(*request))
            .map(|request| self.amount(request))
            .sum()
    }

    /// The next agent's inbox after this client's requests 1 through
    /// `request` applied there.
    fn forwarded(&self, request: u64) -> u64 {
        (1..=request)
            .filter(|request| self.forwards(*request))
            .map(|request| self.amount(request))
            .sum()
    }

    /// A new session from request `first` on, timed by the cluster's clock.
    /// A client that starts them often takes a fresh key for each, as
    /// one without an identity may: one key's sessions are capped.
    fn start(&self, cluster: &Cluster, first: u64) -> Timed {
        let count = self.names.fetch_add(1, Ordering::SeqCst).to_be_bytes();
        let mut name = [0u8; 16];
        name[0] = self.number;
        name[8..].copy_from_slice(&count);
        let mut secret = self.key.to_bytes();
        if !self.forwarding {
            secret[1..9].copy_from_slice(&count);
        }
        let offset = cluster.offset();
        cluster.saw("session started");
        Timed {
            first,
            session: Session {
                key: SigningKey::from_bytes(&secret).verifying_key().to_bytes(),
                name,
                t0: vos_node::wall_clock().saturating_add_signed(offset),
            },
            offset,
            secret,
        }
    }

    /// The session request number `request` goes in, and its sequence
    /// there. The client times the next session ahead, while it uses one,
    /// so a clock jumping meets sessions timed before it.
    fn session(&self, cluster: &Cluster, request: u64) -> (Timed, u64) {
        let mut sessions = self.sessions.lock().unwrap();
        loop {
            let next = sessions.last().map_or(1, |last| last.first + self.rotate);
            if !sessions.is_empty() && request + self.rotate < next {
                break;
            }
            sessions.push(self.start(cluster, next));
        }
        let timed = *sessions
            .iter()
            .rev()
            .find(|timed| timed.first <= request)
            .expect("a session");
        (timed, request - timed.first + 1)
    }

    /// Start a new session at request `first`, in place of any timed
    /// ahead.
    fn rotate_at(&self, cluster: &Cluster, first: u64) {
        let timed = self.start(cluster, first);
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|ahead| ahead.first < first);
        sessions.push(timed);
    }

    /// Time `stale` again, as a new session from the same request: false
    /// when another of its requests already did.
    fn retime(&self, cluster: &Cluster, stale: &Session) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        let Some(at) = sessions.iter().position(|timed| timed.session == *stale) else {
            return false;
        };
        sessions[at] = self.start(cluster, sessions[at].first);
        true
    }

    fn body(&self, timed: &Timed, sequence: u64, request: u64) -> Vec<u8> {
        let session = &timed.session;
        let (method, arguments) = if self.forwards(request) {
            let next = self.next.get().expect("the next agent");
            (
                self.forward,
                (next.0, INBOX.0, self.amount(request)).encode(),
            )
        } else {
            (self.increment, self.amount(request).encode())
        };
        let message = call_message(
            &self.identity,
            session,
            sequence,
            self.instance,
            method,
            &arguments,
        );
        Call {
            session: *session,
            sequence,
            instance: self.instance,
            method,
            arguments,
            signature: SigningKey::from_bytes(&timed.secret)
                .sign(&message)
                .to_bytes(),
        }
        .encode()
    }

    /// Send request `request` until it is answered, following redirects
    /// and moving on from a node that fails; check its answer.
    fn send(&self, cluster: &Cluster, mode: Mode, request: u64) {
        let path = format!("/agents/{}/calls", self.agent.0);
        let until = Instant::now() + ANSWERED;
        self.sent.fetch_max(request, Ordering::SeqCst);
        // Requests take turns at every replica, the leader's followers
        // forwarding to it.
        *self.calling.lock().unwrap() =
            1 + ((request + u64::from(self.number)) % u64::from(NODES)) as NodeNumber;
        loop {
            assert!(
                Instant::now() < until,
                "client {}: request {request} was never answered",
                self.number
            );
            // Its session may have been timed again since the last try.
            let (timed, sequence) = self.session(cluster, request);
            let session = timed.session;
            let body = self.body(&timed, sequence, request);
            let at = *self.calling.lock().unwrap();
            let starts = cluster.slot(at).starts.load(Ordering::SeqCst);
            let next = |client: &Self| {
                *client.calling.lock().unwrap() = at % NODES + 1;
            };
            let offset = cluster.offset();
            match post(cluster.slot(at).ingress, &path, &body) {
                Ok(Answer::Ran {
                    outcome: Outcome::Done(reply),
                    at: answered_at,
                }) => {
                    let total = u64::decode(&reply).unwrap().0;
                    // A forward answers its amount, an increment the total.
                    let expected = if self.forwards(request) {
                        self.amount(request)
                    } else {
                        self.total(request)
                    };
                    assert_eq!(
                        total, expected,
                        "client {}: request {request} answered by node {at}",
                        self.number
                    );
                    self.applied_at(cluster, at, starts, &session, sequence);
                    self.acked.lock().unwrap().answered(request, answered_at);
                    cluster.event(format!(
                        "client {} request {request} (sequence {sequence}) answered by {at}, applied {:?}",
                        self.number,
                        (1..=NODES)
                            .map(|n| cluster.node(n).and_then(|node| node.applied(self.agent)))
                            .collect::<Vec<_>>()
                    ));
                    cluster.saw(if cluster.leader(self.agent) == Some(at) {
                        "answered by the leader"
                    } else {
                        "answered by a follower"
                    });
                    return;
                }
                Ok(Answer::NotLeader {
                    leader: Some(leader),
                }) => {
                    cluster.saw("redirect");
                    match cluster.number_at(&leader.address) {
                        Some(leader) => *self.calling.lock().unwrap() = leader,
                        None => panic!("a redirect to {}", leader.address),
                    }
                }
                Ok(Answer::NotLeader { leader: None } | Answer::Stopped | Answer::TimedOut)
                | Err(_) => {
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
                // Timed before every clock jumped, and sent after: no
                // leader can create it now, so none of its copies runs.
                // Its first request times it again; the others follow.
                Ok(
                    stale @ (Answer::Rejected(Rejection::StaleSession { .. })
                    | Answer::Refused(refusal::STALE_SESSION)),
                ) if timed.offset < offset => {
                    cluster.event(format!(
                        "client {} request {request} (sequence {sequence}) at {at}: {stale:?}",
                        self.number
                    ));
                    if sequence == 1 && self.retime(cluster, &session) {
                        cluster.saw("session timed again");
                    } else {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
                // Sent before the clocks jumped: again, unchanged.
                Ok(
                    Answer::Rejected(Rejection::StaleSession { .. })
                    | Answer::Refused(refusal::STALE_SESSION),
                ) if cluster.offset() > offset => {
                    cluster.saw("stale session across the jump");
                }
                Ok(other) => panic!(
                    "client {}: request {request} (sequence {sequence}) at node {at}: {other:?}; agent {} applied at each node {:?}, leader {:?}\n{}",
                    self.number,
                    self.agent.0,
                    (1..=NODES)
                        .map(|n| cluster.node(n).map(|node| node.applied(self.agent)))
                        .collect::<Vec<_>>(),
                    cluster.leader(self.agent),
                    cluster
                        .events
                        .lock()
                        .unwrap()
                        .iter()
                        .cloned()
                        .collect::<Vec<_>>()
                        .join("\n"),
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

    /// Read the counter until `done`, at every replica in turn, by read
    /// index and at the floor its answers give, and check each read.
    fn read(&self, cluster: &Cluster, done: &AtomicBool, previous: &Client) {
        let mut floor = 0;
        let mut last = 0;
        let mut inbox = 0;
        // The most any read showed.
        let mut seen = 0;
        let mut turn = u64::from(self.number);
        let path = format!("/agents/{}/queries", self.agent.0);
        while !done.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(20));
            turn += 1;
            let at = 1 + (turn % u64::from(NODES)) as NodeNumber;
            let (prefix, prefix_at) = {
                let acked = self.acked.lock().unwrap();
                (acked.prefix, acked.at)
            };
            let linearizable = turn.is_multiple_of(2);
            let consistency = if linearizable {
                Consistency::Linearizable
            } else {
                floor = floor.max(prefix_at);
                Consistency::Applied { at: floor }
            };
            // Now and then the inbox: what the previous client forwarded,
            // in its order.
            if turn.is_multiple_of(3) {
                let answer = post(
                    cluster.slot(at).ingress,
                    &path,
                    &self.query(cluster, INBOX, Consistency::Applied { at: floor }),
                );
                let sent = previous.sent.load(Ordering::SeqCst);
                if let Ok(Answer::Ran {
                    outcome: Outcome::Done(bytes),
                    at: answered_at,
                }) = answer
                {
                    // Reads never go back only at the client's floor, which
                    // this one raises.
                    floor = floor.max(answered_at);
                    let value = u64::decode(&bytes).unwrap().0;
                    assert!(
                        (0..=sent).any(|request| previous.forwarded(request) == value),
                        "client {}: its inbox at node {at} holds {value}, no prefix of what was forwarded",
                        self.number
                    );
                    assert!(
                        value >= inbox,
                        "client {}: its inbox at node {at} went back, from {inbox} to {value}",
                        self.number
                    );
                    inbox = value;
                    cluster.saw("read of an inbox");
                }
                continue;
            }
            let answer = post(
                cluster.slot(at).ingress,
                &path,
                &self.query(cluster, COUNTER, consistency),
            );
            let sent = self.sent.load(Ordering::SeqCst);
            let (value, answered_at) = match answer {
                Ok(Answer::Ran {
                    outcome: Outcome::Done(bytes),
                    at,
                }) => (u64::decode(&bytes).unwrap().0, at),
                // Signed before every clock jumped, a query may be stale.
                Ok(
                    Answer::Rejected(Rejection::Behind | Rejection::StaleQuery { .. })
                    | Answer::TimedOut
                    | Answer::Stopped
                    | Answer::Unavailable
                    | Answer::NotLeader { .. },
                )
                | Err(_) => {
                    cluster.saw("read unanswered");
                    continue;
                }
                Ok(other) => panic!("client {}: a read at node {at}: {other:?}", self.number),
            };
            let earlier = seen;
            seen = seen.max(value);
            // The applied requests are a prefix of those sent: the value is
            // the total of one. A forward leaves the total as it was, so
            // reads compare totals.
            assert!(
                (0..=sent).any(|request| self.total(request) == value),
                "client {}: read {value} at node {at}, no total of up to {sent} requests",
                self.number
            );
            let answered = self.total(prefix);
            if linearizable {
                // Every read before it showed committed state, which a read
                // index taken later covers.
                assert!(
                    value >= earlier,
                    "client {}: a linearizable read at node {at} saw {value}, an earlier read {earlier}",
                    self.number
                );
                assert!(
                    value >= answered,
                    "client {}: a linearizable read at node {at} saw {value}, {prefix} requests answered before it made {answered}",
                    self.number
                );
                cluster.saw("read linearizable");
            } else {
                assert!(
                    value >= last,
                    "client {}: a read at node {at} went back, from {last} to {value}",
                    self.number
                );
                assert!(
                    value >= answered,
                    "client {}: a read at node {at} floored at {floor} saw {value}, {prefix} requests answered at {prefix_at} made {answered}",
                    self.number
                );
                last = value;
                floor = floor.max(answered_at);
                cluster.saw("read at a floor");
            }
        }
    }

    /// A signed query of a counter's value.
    fn query(&self, cluster: &Cluster, instance: InstanceId, consistency: Consistency) -> Vec<u8> {
        let not_after = cluster.time() + 60_000;
        let key = self.key.verifying_key().to_bytes();
        let message = query_message(
            &self.identity,
            &key,
            not_after,
            consistency,
            instance,
            self.value,
            &[],
        );
        QueryCall {
            key,
            not_after,
            consistency,
            instance,
            method: self.value,
            arguments: Vec::new(),
            signature: self.key.sign(&message).to_bytes(),
        }
        .encode()
    }

    /// Send requests until `done`: how many were answered.
    fn run(&self, cluster: &Cluster, mode: Mode, done: &AtomicBool) -> u64 {
        let mut sent = 0;
        while !done.load(Ordering::SeqCst) {
            // Paused with every request answered; then a new session.
            if cluster.paused.load(Ordering::SeqCst) {
                self.idle.store(true, Ordering::SeqCst);
                while cluster.paused.load(Ordering::SeqCst) {
                    std::thread::sleep(Duration::from_millis(5));
                }
                self.idle.store(false, Ordering::SeqCst);
                self.rotate_at(cluster, sent + 1);
                continue;
            }
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

/// [`FAULTS`] failures, one at a time: among them every clock jumping
/// past the skew under load, and every session expiring.
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
        clients
            .iter()
            .all(|client| client.idle.load(Ordering::SeqCst))
    });
    let mut captured = Vec::new();
    for client in clients {
        let sent = client.sent.load(Ordering::SeqCst);
        if sent == 0 {
            continue;
        }
        let (timed, sequence) = client.session(cluster, sent);
        captured.push((client, client.body(&timed, sequence, sent)));
        captured.push((client, client.body(&timed, sequence + 1, sent + 1)));
    }
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
    for (client, body) in &captured {
        let path = format!("/agents/{}/calls", client.agent.0);
        for number in 1..=NODES {
            let until = Instant::now() + ANSWERED;
            loop {
                assert!(Instant::now() < until, "a replay was never answered");
                match post(cluster.slot(number).ingress, &path, body) {
                    Ok(Answer::Rejected(Rejection::StaleSession { .. }) | Answer::TimedOut) => {
                        break;
                    }
                    Ok(
                        Answer::Stopped
                        | Answer::Unavailable
                        | Answer::Busy
                        | Answer::NotLeader { .. },
                    )
                    | Err(_) => std::thread::sleep(Duration::from_millis(10)),
                    Ok(other) => panic!(
                        "client {}: a captured request at node {number}: {other:?}",
                        client.number
                    ),
                }
            }
        }
    }
    cluster.saw("captured requests refused");
    for client in clients {
        let total = client.total(client.sent.load(Ordering::SeqCst));
        for number in 1..=NODES {
            let node = cluster.node(number).unwrap();
            wait_until("every counter as it was", ANSWERED, || {
                counted(&node, client.agent, client.instance, client.value)
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
    let increment = method(&counter, "increment");
    let value = method(&counter, "value");
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
            Client {
                number,
                agent,
                key: SigningKey::from_bytes(&[number; 32]),
                identity,
                increment,
                instance: if forwarding { COUNTER } else { SECOND },
                forwarding,
                // The second clients start sessions often: first requests
                // meet every fault.
                rotate: if forwarding {
                    32 + 4 * random.below(8)
                } else {
                    4 + 4 * random.below(2)
                },
                sessions: Mutex::new(Vec::new()),
                names: AtomicU64::new(0),
                idle: AtomicBool::new(false),
                calling: Mutex::new(1 + (number - 1) % NODES),
                value,
                forward: method(&counter, "forward"),
                next: std::sync::OnceLock::new(),
                sent: AtomicU64::new(0),
                acked: Mutex::new(Acked::default()),
            }
        })
        .collect();
    let forwarding = &clients[..agents.len()];
    for (at, client) in forwarding.iter().enumerate() {
        let next = &forwarding[(at + 1) % forwarding.len()];
        client.next.set(next.agent).unwrap();
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
    println!("{:?}", cluster.seen.lock().unwrap());
    assert!(
        cluster
            .seen
            .lock()
            .unwrap()
            .contains_key("session timed again"),
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
            client.next.get().unwrap(),
        );
        let forwards = sent / 5;
        let inbox = client.forwarded(sent);
        for number in 1..=NODES {
            let node = cluster.node(number).unwrap();
            wait_until("every replica converges", Duration::from_secs(60), || {
                counted(&node, client.agent, COUNTER) == Ok(Outcome::Done(total.encode()))
                    && counted(&node, *next_agent, INBOX) == Ok(Outcome::Done(inbox.encode()))
                    && mark(&node, client.agent, &keys::acked(*next_agent)) == forwards
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
                mark(&node, client.agent, &keys::pair_out(*next_agent)),
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
