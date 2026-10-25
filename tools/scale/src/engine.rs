//! `drive-local`: one driver's share of the load model, open loop. A
//! planning thread draws the operations in time order and signs each ahead
//! of its scheduled send; the sending thread sends each at its time, one
//! attempt, over at most [`MAX_CONNECTIONS`] kept connections a node, and
//! counts every refusal by its kind. A user's calls go one at a time in
//! its session, in order: one scheduled while the last is unanswered waits
//! for it, its latency still timed from its schedule. A call refused before
//! it ran gives its sequence to the next; one whose fate is unknown ends
//! the session, and the user's next call starts another. Every interval a
//! line a kind goes to the record: the histogram's quantiles, the rate and
//! the errors.

use std::cell::{Cell, RefCell};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::Write;
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::Path;
use std::rc::Rc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use futures_rustls::TlsConnector;
use rustls::pki_types::ServerName;
use smol::channel::{Receiver, Sender};
use smol::io::{AsyncReadExt, AsyncWriteExt};
use smol::net::TcpStream;
use smol::{LocalExecutor, Timer};
use vos_node::client::{
    Target, signed_call, signed_query, signed_workflow_read, workflow_read_not_after,
};
use vos_wire::abi::{AttestError, Refusal};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Session, WorkflowId};
use vos_wire::ingress::{Consistency, Rejection, Response, WorkflowStatus};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};

use crate::drive::{LATE_US, Plan};
use crate::histogram::Histogram;
use crate::load::{self, Kind, Planned, Users};
use crate::nodes::target;

/// The most connections a driver keeps to one node.
pub const MAX_CONNECTIONS: usize = 512;
/// How far ahead of its schedule an operation is signed.
const LOOKAHEAD: Duration = Duration::from_millis(500);
/// How early an operation may go rather than wait for a timer: it is then
/// timed from its send, not its schedule.
const EARLY: Duration = Duration::from_micros(200);
/// The least the planning thread sleeps once far enough ahead.
const PLAN_NAP: Duration = Duration::from_millis(50);
/// How long one request may take before the driver counts it failed:
/// past it, a reaper that wakes every [`REAP`] closes its connection. A
/// timer a request would cost as much as the request, at the driver's
/// rates.
const ANSWER: Duration = Duration::from_secs(30);
const REAP: Duration = Duration::from_secs(1);
/// How long a connection may take to open.
const CONNECT: Duration = Duration::from_secs(10);
/// A kept connection is used again only if idle less than this long, well
/// within the node's idle limit.
const REUSE: Duration = Duration::from_secs(20);
/// The most a read takes at once: an answer is a few hundred bytes.
const READ_CHUNK: usize = 4 << 10;
/// Connections opened to each node before the load starts.
const WARM: usize = 64;
/// How long a read of a workflow waits for it to end.
const WORKFLOW_WAIT_MS: u64 = 2_000;
/// A read at a cut: the first read's wait once its window closed, the
/// pause between reads after, and how long past the close it keeps asking.
const CUT_WAIT_MS: u64 = 10_000;
const CUT_POLL: Duration = Duration::from_secs(2);
const CUT_GIVE_UP_MS: u64 = 60_000;
/// How long past its `not_after` a query is good: within the node's
/// horizon.
const QUERY_GOOD_MS: u64 = 60_000;
/// The identity writes are signed by these users, none of the model's, in
/// turn: each writer's calls go one at a time, so several keep the rate
/// whatever the latency.
const IDENTITY_WRITERS: u64 = 16;
const IDENTITY_WRITER: u64 = u64::MAX - IDENTITY_WRITERS;
/// What a transfer moves.
const AMOUNT: u64 = 1;

fn wall_ms() -> u64 {
    crate::now_ms()
}

/// The methods the load calls, by name in the shard actor's schema.
#[derive(Clone, Copy)]
struct Methods {
    transfer: MethodId,
    balance: MethodId,
    tally: MethodId,
    holds_at_cut: MethodId,
    set_identity: MethodId,
}

/// An agent the load calls: its id, its identity (which its calls are
/// signed for) and its replicas by node index.
struct Agent {
    id: AgentId,
    identity: [u8; 32],
    replicas: Vec<usize>,
    paths: [String; 3],
}

/// A user's session at its agent, as the driver keeps it.
struct UserSession {
    key: SigningKey,
    name: [u8; 16],
    t0: u64,
    /// Bumped at each new session: a call signed in an older one is
    /// signed again when its turn comes.
    generation: u32,
    /// The sequence the next planned call is signed at, and the next one
    /// sent: they differ by the calls planned and not yet sent.
    planned_next: u64,
    sent_next: u64,
    unsent: u64,
    floor: u64,
    busy: bool,
    queue: VecDeque<Op>,
}

/// What every thread shares.
struct Shared {
    /// The ledger shards, then the identity agent if there is one.
    agents: Vec<Agent>,
    identity_agent: Option<usize>,
    instance: InstanceId,
    methods: Methods,
    seed: u64,
    sessions: Mutex<HashMap<u64, UserSession>>,
    /// How far the agents' time runs ahead of this host's clock, as a
    /// node last said.
    offset_ms: AtomicI64,
}

impl Shared {
    fn agent_now(&self) -> u64 {
        wall_ms().saturating_add_signed(self.offset_ms.load(Ordering::Relaxed))
    }

    fn key(&self, user: u64) -> SigningKey {
        SigningKey::from_bytes(&load::user(self.seed, user).0)
    }

    fn session_name(&self, user: u64, generation: u32) -> [u8; 16] {
        let mut input = b"vos-scale session".to_vec();
        input.extend(self.seed.to_le_bytes());
        input.extend(user.to_le_bytes());
        input.extend(generation.to_le_bytes());
        input.extend(wall_ms().to_le_bytes());
        vos_pvm::precompile::blake2b_256(&input)[..16]
            .try_into()
            .expect("16 bytes")
    }

    /// `user`'s session, opened if it has none: its key derived outside
    /// the lock.
    fn open(&self, user: u64) {
        if self.sessions.lock().expect("sessions").contains_key(&user) {
            return;
        }
        let key = self.key(user);
        let generation = 0;
        let session = UserSession {
            key,
            name: self.session_name(user, generation),
            t0: self.agent_now(),
            generation,
            planned_next: 1,
            sent_next: 1,
            unsent: 0,
            floor: 0,
            busy: false,
            queue: VecDeque::new(),
        };
        self.sessions
            .lock()
            .expect("sessions")
            .entry(user)
            .or_insert(session);
    }

    /// A new session for `session`'s user, its calls not yet sent to be
    /// signed again in it.
    fn renew(&self, user: u64, session: &mut UserSession) {
        session.generation += 1;
        session.name = self.session_name(user, session.generation);
        session.t0 = self.agent_now();
        session.sent_next = 1;
        session.planned_next = 1 + session.unsent;
    }

    fn call_body(
        &self,
        agent: usize,
        session: &UserSession,
        sequence: u64,
        method: MethodId,
        arguments: &[u8],
    ) -> Vec<u8> {
        signed_call(
            &self.agents[agent].identity,
            &session.key,
            Session {
                key: session.key.verifying_key().to_bytes(),
                name: session.name,
                t0: session.t0,
            },
            sequence,
            self.instance,
            method,
            arguments.to_vec(),
        )
        .encode()
    }

    /// `planned` as an operation due at `due`, signed.
    fn operation(&self, planned: &Planned, users: &Users, due: Instant) -> Op {
        let account = load::account(self.seed, planned.user);
        let home = match planned.kind {
            Kind::Identity => self.identity_agent.expect("an identity agent"),
            _ => users.shard(planned.user),
        };
        let (method, arguments) = match planned.kind {
            Kind::Transfer => {
                let (payee, _) = planned.payee.expect("a transfer's payee");
                let to_agent = self.agents[users.shard(payee)].id.0;
                let arguments = [
                    &account[..],
                    &load::account(self.seed, payee)[..],
                    &to_agent.to_le_bytes(),
                    &AMOUNT.to_le_bytes(),
                ]
                .concat();
                (self.methods.transfer, arguments)
            }
            Kind::Query => (self.methods.balance, account.to_vec()),
            Kind::Workflow => (self.methods.tally, vec![1u64, 2, 3].encode()),
            Kind::Cut => (
                self.methods.holds_at_cut,
                [&1u64.to_le_bytes()[..], &account[..]].concat(),
            ),
            Kind::Identity => (
                self.methods.set_identity,
                [&planned.user.to_le_bytes()[..], &[0x1d; 32]].concat(),
            ),
        };
        let user = if planned.kind == Kind::Identity {
            IDENTITY_WRITER + planned.user % IDENTITY_WRITERS
        } else {
            planned.user
        };
        let cross = planned.payee.is_some_and(|(_, cross)| cross);
        self.open(user);
        let mut sessions = self.sessions.lock().expect("sessions");
        let session = sessions.get_mut(&user).expect("an open session");
        if planned.kind == Kind::Query {
            let key = session.key.clone();
            let floor = session.floor;
            drop(sessions);
            let body = signed_query(
                &self.agents[home].identity,
                &key,
                self.agent_now() + QUERY_GOOD_MS,
                Consistency::Applied { at: floor },
                self.instance,
                method,
                arguments,
            )
            .encode();
            return Op {
                due,
                kind: planned.kind,
                user,
                agent: home,
                cross,
                body: Body::Query(body),
            };
        }
        // A session's time is its first call's: one opened before the load,
        // or long before its user acted, would be refused as stale.
        if session.planned_next == 1 && session.unsent == 0 {
            session.t0 = self.agent_now();
        }
        let sequence = session.planned_next;
        session.planned_next += 1;
        session.unsent += 1;
        let generation = session.generation;
        let key = session.key.clone();
        let (name, t0) = (session.name, session.t0);
        drop(sessions);
        let signed = signed_call(
            &self.agents[home].identity,
            &key,
            Session {
                key: key.verifying_key().to_bytes(),
                name,
                t0,
            },
            sequence,
            self.instance,
            method,
            arguments.clone(),
        )
        .encode();
        Op {
            due,
            kind: planned.kind,
            user,
            agent: home,
            cross,
            body: Body::Call {
                method,
                arguments,
                generation,
                sequence,
                signed,
            },
        }
    }
}

/// One operation, signed for its schedule.
struct Op {
    due: Instant,
    kind: Kind,
    user: u64,
    agent: usize,
    cross: bool,
    body: Body,
}

enum Body {
    Call {
        method: MethodId,
        arguments: Vec<u8>,
        generation: u32,
        sequence: u64,
        signed: Vec<u8>,
    },
    Query(Vec<u8>),
}

/// What became of a call, for its session.
#[derive(Debug, PartialEq, Eq)]
enum Fate {
    /// It ran: its sequence is spent, its answer reflects state `at`.
    Ran(u64),
    /// It never ran: its sequence goes to the next call.
    NeverRan,
    /// It may have run, or its session is gone: the next call starts a
    /// new session.
    Renew,
}

fn fate(answer: &Result<Response, String>) -> Fate {
    match answer {
        Ok(Response::Ran { at, .. }) => Fate::Ran(*at),
        Ok(
            Response::Rejected(Rejection::StaleSession { .. })
            | Response::Refused(Refusal::Expired | Refusal::StaleSession),
        ) => Fate::Renew,
        Ok(
            Response::Rejected(_)
            | Response::Refused(Refusal::SessionsFull | Refusal::KeySessionsFull)
            | Response::Busy
            | Response::NotLeader { .. }
            | Response::Elsewhere { .. }
            | Response::Unavailable
            | Response::NoAgent
            | Response::NotConsumed,
        ) => Fate::NeverRan,
        _ => Fate::Renew,
    }
}

/// A refusal's name: its variant, and for `Rejected`, `Refused` and a
/// failed outcome, the inner one.
pub fn refusal(answer: &Result<Response, String>) -> String {
    let response = match answer {
        Ok(response) => response,
        Err(error) => return format!("client: {error}"),
    };
    let name = match response {
        Response::Ran {
            outcome: Outcome::Failed { code, detail },
            ..
        }
        | Response::Workflow {
            status: WorkflowStatus::Ended(Outcome::Failed { code, detail }),
            ..
        } => {
            return match AttestError::decode(detail) {
                Ok((error, _)) if *code == vos_wire::abi::Failure::Handler => {
                    format!("Failed({code:?}: {error:?})")
                }
                _ => format!("Failed({code:?})"),
            };
        }
        Response::Rejected(rejection) => return format!("Rejected({})", variant(rejection)),
        Response::Refused(refused) => return format!("Refused({})", variant(refused)),
        Response::Workflow { status, .. } => return format!("Workflow({})", variant(status)),
        Response::Ran { .. } => "Ran",
        Response::NotConsumed => "NotConsumed",
        Response::Busy => "Busy",
        Response::NoAgent => "NoAgent",
        Response::Stopped => "Stopped",
        Response::Created(_) => "Created",
        Response::Unavailable => "Unavailable",
        Response::NotLeader { .. } => "NotLeader",
        Response::Elsewhere { .. } => "Elsewhere",
        Response::Unconfirmed(_) => "Unconfirmed",
        Response::TimedOut => "TimedOut",
        Response::Placed(_) => "Placed",
        Response::Unplaced(_) => "Unplaced",
        Response::Status(_) => "Status",
        Response::Stats(_) => "Stats",
    };
    name.to_string()
}

/// A small enum's variant, by the first word its `Debug` writes.
fn variant(value: &impl std::fmt::Debug) -> String {
    let text = format!("{value:?}");
    text.split(|c: char| !(c.is_alphanumeric() || c == '_'))
        .find(|word| !word.is_empty())
        .unwrap_or("?")
        .to_string()
}

/// One kind's counts over an interval, or the whole load.
#[derive(Clone, Default)]
struct KindStats {
    sent: u64,
    ok: u64,
    latency: Histogram,
    errors: BTreeMap<String, u64>,
    /// How long the refused took to be answered.
    refused: Histogram,
    /// Sends more than [`LATE_US`] behind their schedule, and the latest.
    late_sends: u64,
    late_us: u64,
    /// Calls that waited behind their user's last, unanswered one.
    queued: u64,
    /// Transfers to another shard.
    cross: u64,
}

impl KindStats {
    fn absorb(&mut self, other: &KindStats) {
        self.sent += other.sent;
        self.ok += other.ok;
        self.latency.add(&other.latency);
        self.refused.add(&other.refused);
        for (kind, count) in &other.errors {
            *self.errors.entry(kind.clone()).or_default() += count;
        }
        self.late_sends += other.late_sends;
        self.late_us = self.late_us.max(other.late_us);
        self.queued += other.queued;
        self.cross += other.cross;
    }

    fn line(&self, t_ms: u64, seconds: f64, kind: &str, total: bool) -> serde_json::Value {
        let errors: u64 = self.errors.values().sum();
        let seconds = seconds.max(1e-9);
        serde_json::json!({
            "t_ms": t_ms,
            "total": total,
            "kind": kind,
            "sent": self.sent,
            "offered": self.sent as f64 / seconds,
            "ok": self.ok,
            "errors": errors,
            "by_error": self.errors,
            "rate": self.ok as f64 / seconds,
            "p50_us": self.latency.quantile(0.5),
            "p99_us": self.latency.quantile(0.99),
            "p999_us": self.latency.quantile(0.999),
            "refused_p50_us": self.refused.quantile(0.5),
            "refused_p99_us": self.refused.quantile(0.99),
            "late_us": self.late_us,
            "late_sends": self.late_sends,
            "queued": self.queued,
            "cross": self.cross,
        })
    }
}

/// The kinds a record reports: the mix's, the identity writes, and the
/// reads that wait for a cut's close.
const REPORTED: [&str; 6] = [
    "transfer", "query", "workflow", "cut", "cut_read", "identity",
];

#[derive(Default)]
struct Stats {
    kinds: BTreeMap<&'static str, KindStats>,
}

impl Stats {
    fn kind(&mut self, name: &'static str) -> &mut KindStats {
        self.kinds.entry(name).or_default()
    }

    /// The mix's kinds together.
    fn mix(&self) -> KindStats {
        let mut all = KindStats::default();
        for kind in Kind::MIX {
            if let Some(stats) = self.kinds.get(kind.name()) {
                all.absorb(stats);
            }
        }
        all
    }
}

/// A connection's stream, plain or in TLS.
enum Stream {
    Plain(TcpStream),
    Tls(Box<futures_rustls::client::TlsStream<TcpStream>>),
}

struct Conn {
    stream: Stream,
    /// Its socket, which the reaper shuts when a request on it is late.
    socket: TcpStream,
    /// Bytes read past the last answer.
    buffer: Vec<u8>,
    /// When its last answer came: one idle past [`REUSE`] is closed, not
    /// used, as the node may have closed it.
    used: Instant,
}

impl Conn {
    async fn write_all(&mut self, bytes: &[u8]) -> std::io::Result<()> {
        match &mut self.stream {
            Stream::Plain(stream) => {
                stream.write_all(bytes).await?;
                stream.flush().await
            }
            Stream::Tls(stream) => {
                stream.write_all(bytes).await?;
                stream.flush().await
            }
        }
    }

    /// Read what has arrived onto the buffer's end: how much.
    async fn read_more(&mut self) -> std::io::Result<usize> {
        let at = self.buffer.len();
        self.buffer.resize(at + READ_CHUNK, 0);
        let read = match &mut self.stream {
            Stream::Plain(stream) => stream.read(&mut self.buffer[at..]).await,
            Stream::Tls(stream) => stream.read(&mut self.buffer[at..]).await,
        };
        self.buffer.truncate(at + *read.as_ref().unwrap_or(&0));
        read
    }

    /// The next answer: its status, its body, and whether the node closes
    /// the connection after it.
    async fn answer(&mut self) -> std::io::Result<(u16, Vec<u8>, bool)> {
        let invalid =
            |why: &str| std::io::Error::new(std::io::ErrorKind::InvalidData, why.to_string());
        loop {
            let mut headers = [httparse::EMPTY_HEADER; 32];
            let mut answer = httparse::Response::new(&mut headers);
            match answer.parse(&self.buffer) {
                Ok(httparse::Status::Complete(head)) => {
                    let status = answer.code.unwrap_or(0);
                    let header = |name: &str| {
                        answer
                            .headers
                            .iter()
                            .find(|header| header.name.eq_ignore_ascii_case(name))
                            .map(|header| header.value)
                    };
                    let length: usize = header("content-length")
                        .and_then(|value| std::str::from_utf8(value).ok()?.trim().parse().ok())
                        .ok_or_else(|| invalid("an answer without a length"))?;
                    if length > 16 << 20 {
                        return Err(invalid("an answer larger than any the node gives"));
                    }
                    let close = header("connection")
                        .is_some_and(|value| value.eq_ignore_ascii_case(b"close"));
                    while self.buffer.len() < head + length {
                        if self.read_more().await? == 0 {
                            return Err(invalid("the answer ended early"));
                        }
                    }
                    let body = self.buffer[head..head + length].to_vec();
                    self.buffer.drain(..head + length);
                    return Ok((status, body, close));
                }
                Ok(httparse::Status::Partial) => {
                    if self.buffer.len() > 64 << 10 {
                        return Err(invalid("an answer's head too large"));
                    }
                    if self.read_more().await? == 0 {
                        return Err(invalid("the connection closed"));
                    }
                }
                Err(_) => return Err(invalid("an answer that is not HTTP")),
            }
        }
    }
}

/// Kept connections to one node: at most [`MAX_CONNECTIONS`], a request
/// on each at a time; past them, a request waits for one.
struct Pool {
    addresses: Vec<SocketAddr>,
    tls: Option<(TlsConnector, ServerName<'static>)>,
    authority: String,
    /// Kept connections, the last used on top: a few stay busy, and the
    /// rest age out unused.
    idle: RefCell<Vec<Conn>>,
    open: Cell<usize>,
    waiting: RefCell<VecDeque<Sender<Option<Conn>>>>,
    /// Requests on their connections, by number: each one's deadline, and
    /// its socket, which the reaper shuts past it.
    asked: RefCell<HashMap<u64, (Instant, TcpStream)>>,
    next: Cell<u64>,
}

impl Pool {
    fn new(target: &Target) -> Result<Self, String> {
        let addresses: Vec<SocketAddr> = target
            .authority()
            .to_socket_addrs()
            .map_err(|error| format!("{}: {error}", target.authority()))?
            .collect();
        Ok(Self {
            addresses,
            tls: target
                .tls()
                .map(|(config, name)| (TlsConnector::from(config), name)),
            authority: target.authority().to_string(),
            idle: RefCell::new(Vec::new()),
            open: Cell::new(0),
            waiting: RefCell::new(VecDeque::new()),
            asked: RefCell::new(HashMap::new()),
            next: Cell::new(0),
        })
    }

    async fn connect(&self) -> std::io::Result<Conn> {
        let mut last = None;
        for address in &self.addresses {
            match TcpStream::connect(*address).await {
                Ok(tcp) => {
                    tcp.set_nodelay(true)?;
                    let socket = tcp.clone();
                    let stream = match &self.tls {
                        Some((connector, name)) => {
                            let handshake =
                                async { connector.connect(name.clone(), tcp).await.map(Some) };
                            let late = async {
                                Timer::after(CONNECT).await;
                                Ok(None)
                            };
                            match smol::future::or(handshake, late).await? {
                                Some(tls) => Stream::Tls(Box::new(tls)),
                                None => return Err(std::io::ErrorKind::TimedOut.into()),
                            }
                        }
                        None => Stream::Plain(tcp),
                    };
                    return Ok(Conn {
                        stream,
                        socket,
                        buffer: Vec::new(),
                        used: Instant::now(),
                    });
                }
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| std::io::Error::other("the node has no address")))
    }

    /// A kept connection, a new one while fewer than the most are open, or
    /// the next one given back; `held` once it holds a place among them.
    async fn take(&self, held: &Held<'_>) -> std::io::Result<Conn> {
        let kept = self.idle.borrow_mut().pop();
        if let Some(conn) = kept {
            held.0.set(true);
            if conn.used.elapsed() < REUSE {
                return Ok(conn);
            }
            // Stale: closed, its place taken by this request.
            drop(conn);
            return self.connect().await;
        }
        if self.open.get() >= MAX_CONNECTIONS {
            let (sender, receiver) = smol::channel::bounded(1);
            self.waiting.borrow_mut().push_back(sender);
            let mut waiting = Waiting(self, Some(receiver));
            let given = match &waiting.1 {
                Some(receiver) => receiver.recv().await,
                None => unreachable!("waiting"),
            };
            waiting.1 = None;
            match given {
                Ok(Some(conn)) => {
                    held.0.set(true);
                    return Ok(conn);
                }
                // A connection closed, its place given to this request.
                Ok(None) => {
                    held.0.set(true);
                    return self.connect().await;
                }
                Err(_) => return Err(std::io::Error::other("the pool closed")),
            }
        }
        self.open.set(self.open.get() + 1);
        held.0.set(true);
        self.connect().await
    }

    /// A connection back, or `None` for one that closed: its place goes to
    /// the next request waiting.
    fn give(&self, conn: Option<Conn>) {
        match conn {
            Some(mut conn) => {
                conn.used = Instant::now();
                // The longest idle, at the bottom, are closed before the node
                // closes them, not found stale when a burst needs them.
                let stale = {
                    let mut idle = self.idle.borrow_mut();
                    let stale = idle
                        .iter()
                        .take_while(|kept| kept.used.elapsed() >= REUSE)
                        .count();
                    idle.drain(..stale).count()
                };
                self.open.set(self.open.get() - stale);
                loop {
                    let Some(waiter) = self.waiting.borrow_mut().pop_front() else {
                        break;
                    };
                    match waiter.try_send(Some(conn)) {
                        Ok(()) => return,
                        Err(error) => conn = error.into_inner().expect("the connection"),
                    }
                }
                self.idle.borrow_mut().push(conn);
            }
            None => {
                loop {
                    let Some(waiter) = self.waiting.borrow_mut().pop_front() else {
                        break;
                    };
                    if waiter.try_send(None).is_ok() {
                        return;
                    }
                }
                self.open.set(self.open.get() - 1);
            }
        }
    }

    /// Open a connection and keep it: a handshake done before the load
    /// starts.
    async fn warm(&self) {
        self.open.set(self.open.get() + 1);
        match self.connect().await {
            Ok(conn) => self.give(Some(conn)),
            Err(_) => self.give(None),
        }
    }

    /// POST `body` to `path`: the node's answer, within `within`.
    async fn post(&self, path: &str, body: &[u8], within: Duration) -> Result<Response, String> {
        let held = Held(Cell::new(false), self);
        let exchange = async {
            let mut conn = match self.take(&held).await {
                Ok(conn) => conn,
                Err(error) => return Err(error.to_string()),
            };
            let mut request = format!(
                "POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Length: {}\r\n\r\n",
                self.authority,
                body.len()
            )
            .into_bytes();
            request.extend_from_slice(body);
            let id = self.next.get();
            self.next.set(id + 1);
            self.asked
                .borrow_mut()
                .insert(id, (Instant::now() + within, conn.socket.clone()));
            let answered = match conn.write_all(&request).await {
                Ok(()) => conn.answer().await,
                Err(error) => Err(error),
            };
            let reaped = self.asked.borrow_mut().remove(&id).is_none();
            held.0.set(false);
            match answered {
                Ok((status, answer, close)) => {
                    self.give((!close).then_some(conn));
                    Response::decode(&answer)
                        .map(|(response, _)| response)
                        .map_err(|_| format!("an answer it cannot read (status {status})"))
                }
                Err(_) if reaped => {
                    self.give(None);
                    Err("timed out".into())
                }
                Err(error) => {
                    self.give(None);
                    Err(error.kind().to_string())
                }
            }
        };
        exchange.await
    }

    /// Shut the connections whose requests are past their deadlines: each
    /// request then fails, timed out.
    fn reap(&self) {
        let now = Instant::now();
        self.asked.borrow_mut().retain(|_, (deadline, socket)| {
            let late = *deadline <= now;
            if late {
                let _ = socket.shutdown(std::net::Shutdown::Both);
            }
            !late
        });
    }
}

/// A request's place among a pool's connections: given back as closed if
/// the request is dropped holding it.
struct Held<'a>(Cell<bool>, &'a Pool);

impl Drop for Held<'_> {
    fn drop(&mut self) {
        if self.0.get() {
            self.1.give(None);
        }
    }
}

/// A request waiting for a connection: if it ends first, what it was
/// given goes back.
struct Waiting<'a>(&'a Pool, Option<Receiver<Option<Conn>>>);

impl Drop for Waiting<'_> {
    fn drop(&mut self) {
        if let Some(Ok(given)) = self.1.as_ref().map(Receiver::try_recv) {
            self.0.give(given);
        }
    }
}

/// The sending thread's state.
struct Engine {
    shared: Arc<Shared>,
    pools: Vec<Pool>,
    /// Each agent's leader as last learned, by node index.
    leaders: RefCell<Vec<usize>>,
    stats: RefCell<Stats>,
    whole: RefCell<Stats>,
    /// Operations whose last request is unanswered, reads at a cut
    /// waiting for their window's close among them.
    inflight: Cell<u64>,
    ex: &'static LocalExecutor<'static>,
    /// The space's window clock: its origin and length, in ms; and `D`,
    /// how long after a window's boundary its close comes.
    window: (u64, u64, u64),
    /// Every request to a node that does not replicate its agent:
    /// [`Plan::probe`].
    probe: bool,
}

impl Engine {
    /// A node that does not replicate `agent`: a probe's target.
    fn elsewhere(&self, agent: usize) -> usize {
        let replicas = &self.shared.agents[agent].replicas;
        (0..self.pools.len())
            .find(|node| !replicas.contains(node))
            .unwrap_or(replicas[0])
    }

    fn record(&self, kind: &'static str, update: impl FnOnce(&mut KindStats)) {
        update(self.stats.borrow_mut().kind(kind));
    }

    fn done(&self, kind: &'static str, due: Instant, answer: &Result<Response, String>) {
        let ok = matches!(
            answer,
            Ok(Response::Ran {
                outcome: Outcome::Done(_) | Outcome::Started(_),
                ..
            }) | Ok(Response::Workflow {
                status: WorkflowStatus::Ended(Outcome::Done(_)),
                ..
            })
        );
        let took = Instant::now().saturating_duration_since(due).as_micros() as u64;
        self.record(kind, |stats| {
            if ok {
                stats.ok += 1;
                stats.latency.record(took);
            } else {
                *stats.errors.entry(refusal(answer)).or_default() += 1;
                stats.refused.record(took);
            }
        });
    }

    /// Take `op` at its time: send it, or queue it behind its user's
    /// unanswered call.
    fn dispatch(self: &Rc<Self>, mut op: Op) {
        let now = Instant::now();
        let late = now.saturating_duration_since(op.due).as_micros() as u64;
        // Sent a little early, to spare a timer: timed from its send.
        op.due = op.due.max(now);
        self.record(op.kind.name(), |stats| {
            stats.sent += 1;
            stats.cross += u64::from(op.cross);
            stats.late_us = stats.late_us.max(late);
            stats.late_sends += u64::from(late > LATE_US);
        });
        self.inflight.set(self.inflight.get() + 1);
        let kind = op.kind.name();
        if matches!(op.body, Body::Query(_)) {
            let this = Rc::clone(self);
            self.ex.spawn(async move { this.query(op).await }).detach();
            return;
        }
        let ready = {
            let mut sessions = self.shared.sessions.lock().expect("sessions");
            let session = sessions
                .get_mut(&op.user)
                .expect("a planned user's session");
            if session.busy {
                session.queue.push_back(op);
                None
            } else {
                session.busy = true;
                Some(self.prepare(session, op))
            }
        };
        match ready {
            Some(op) => {
                let this = Rc::clone(self);
                self.ex.spawn(async move { this.call(op).await }).detach();
            }
            None => self.record(kind, |stats| stats.queued += 1),
        }
    }

    /// `op` ready to send in `session`: signed again unless it was signed
    /// at the session's next sequence.
    fn prepare(&self, session: &mut UserSession, mut op: Op) -> Op {
        let agent = op.agent;
        if let Body::Call {
            method,
            arguments,
            generation,
            sequence,
            signed,
        } = &mut op.body
        {
            session.unsent -= 1;
            if *generation != session.generation || *sequence != session.sent_next {
                *signed =
                    self.shared
                        .call_body(agent, session, session.sent_next, *method, arguments);
                *generation = session.generation;
                *sequence = session.sent_next;
            }
            session.sent_next += 1;
        }
        op
    }

    async fn query(self: Rc<Self>, op: Op) {
        let Body::Query(body) = &op.body else {
            unreachable!("a query")
        };
        let agent = &self.shared.agents[op.agent];
        // A follower: one of the replicas the leader is not, by user.
        let leader = self.leaders.borrow()[op.agent];
        let followers: Vec<usize> = agent
            .replicas
            .iter()
            .copied()
            .filter(|node| *node != leader)
            .collect();
        let node = match followers.len() {
            _ if self.probe => self.elsewhere(op.agent),
            0 => leader,
            n => followers[(op.user % n as u64) as usize],
        };
        let answer = self.pools[node].post(&agent.paths[1], body, ANSWER).await;
        self.done(op.kind.name(), op.due, &answer);
        self.inflight.set(self.inflight.get() - 1);
    }

    async fn call(self: Rc<Self>, op: Op) {
        let Body::Call {
            signed, sequence, ..
        } = &op.body
        else {
            unreachable!("a call")
        };
        let agent = &self.shared.agents[op.agent];
        let node = match self.probe {
            true => self.elsewhere(op.agent),
            false => self.leaders.borrow()[op.agent],
        };
        let answer = self.pools[node].post(&agent.paths[0], signed, ANSWER).await;
        // A probe's calls are refused before they reach a session: its
        // sequences go on as if each ran, as they would at the leader.
        let fate = match self.probe {
            true => Fate::Ran(0),
            false => fate(&answer),
        };
        if let Ok(Response::NotLeader {
            leader: Some(contact),
        }) = &answer
            && let Some(at) = agent.replicas.iter().position(|node| {
                self.pools[*node].authority.ends_with(
                    contact
                        .address
                        .rsplit("//")
                        .next()
                        .unwrap_or(&contact.address),
                )
            })
        {
            self.leaders.borrow_mut()[op.agent] = agent.replicas[at];
        }
        if let Ok(Response::Rejected(Rejection::StaleSession { now })) = &answer {
            let offset = i128::from(*now) - i128::from(wall_ms());
            self.shared.offset_ms.store(
                offset.clamp(i64::MIN.into(), i64::MAX.into()) as i64,
                Ordering::Relaxed,
            );
        }
        // The session goes on before any read of a workflow: the user's
        // next call need not wait for it.
        let next = {
            let mut sessions = self.shared.sessions.lock().expect("sessions");
            let session = sessions
                .get_mut(&op.user)
                .expect("a sending user's session");
            match fate {
                Fate::Ran(at) => session.floor = session.floor.max(at),
                Fate::NeverRan => {
                    session.sent_next = *sequence;
                    session.planned_next = session.sent_next + session.unsent;
                }
                Fate::Renew => self.shared.renew(op.user, session),
            }
            session.busy = false;
            match session.queue.pop_front() {
                Some(next) => {
                    session.busy = true;
                    Some(self.prepare(session, next))
                }
                None => None,
            }
        };
        if let Some(next) = next {
            let this = Rc::clone(&self);
            self.ex.spawn(async move { this.call(next).await }).detach();
        }
        let started = match &answer {
            Ok(Response::Ran {
                outcome: Outcome::Started(workflow),
                ..
            }) => Some(*workflow),
            _ => None,
        };
        match (op.kind, started) {
            (Kind::Workflow, Some(workflow)) => {
                let read = self
                    .read_workflow(&op, node, workflow, WORKFLOW_WAIT_MS)
                    .await;
                self.done("workflow", op.due, &read);
            }
            (Kind::Cut, Some(workflow)) => {
                self.done("cut", op.due, &answer);
                self.read_at_cut(&op, node, workflow).await;
            }
            (kind, _) => self.done(kind.name(), op.due, &answer),
        }
        self.inflight.set(self.inflight.get() - 1);
    }

    /// A signed read of `workflow`, waiting up to `wait_ms` for it to end.
    async fn read_workflow(
        &self,
        op: &Op,
        node: usize,
        workflow: WorkflowId,
        wait_ms: u64,
    ) -> Result<Response, String> {
        let (key, floor) = {
            let sessions = self.shared.sessions.lock().expect("sessions");
            let session = &sessions[&op.user];
            (session.key.clone(), session.floor)
        };
        let agent = &self.shared.agents[op.agent];
        let read = signed_workflow_read(
            &agent.identity,
            &key,
            workflow_read_not_after(self.shared.agent_now(), wait_ms),
            Consistency::Applied { at: floor },
            workflow,
            wait_ms,
        )
        .encode();
        self.pools[node]
            .post(
                &agent.paths[2],
                &read,
                ANSWER + Duration::from_millis(wait_ms),
            )
            .await
    }

    /// A read at a cut, once started: read once to learn its window, then
    /// again from its close, `B_w + D`, until it ends. Its latency is from
    /// the close: whether every read is served within 10 s of it.
    async fn read_at_cut(&self, op: &Op, node: usize, workflow: WorkflowId) {
        let first = self.read_workflow(op, node, workflow, 0).await;
        let (origin, length, delay) = self.window;
        let close = match &first {
            Ok(Response::Workflow {
                status: WorkflowStatus::Attesting { window, deadline },
                ..
            }) => match length {
                0 => *deadline,
                length => origin + (window + 1) * length + delay,
            },
            other => {
                // Ended already, or refused: no wait for a close.
                return self.done("cut_read", Instant::now(), other);
            }
        };
        let wait = Duration::from_millis(close.saturating_sub(self.shared.agent_now()));
        Timer::after(wait).await;
        let closed = Instant::now();
        let last = loop {
            let asked = Instant::now();
            let read = self.read_workflow(op, node, workflow, CUT_WAIT_MS).await;
            let ended = matches!(
                read,
                Ok(Response::Workflow {
                    status: WorkflowStatus::Ended(_),
                    ..
                })
            );
            if ended || closed.elapsed() > Duration::from_millis(CUT_GIVE_UP_MS) {
                break read;
            }
            if asked.elapsed() < CUT_POLL {
                Timer::after(CUT_POLL - asked.elapsed()).await;
            }
        };
        self.done("cut_read", closed, &last);
    }

    /// Every interval, and once more at the end: a line a kind.
    fn flush(&self, file: &mut std::fs::File, seconds: f64) {
        let taken = std::mem::take(&mut *self.stats.borrow_mut());
        let t_ms = wall_ms();
        for name in REPORTED {
            if let Some(stats) = taken.kinds.get(name) {
                let _ = writeln!(file, "{}", stats.line(t_ms, seconds, name, false));
            }
        }
        let mut line = taken.mix().line(t_ms, seconds, "all", false);
        line["cpu_s"] = cpu_seconds().into();
        let _ = writeln!(file, "{line}");
        let mut whole = self.whole.borrow_mut();
        for (name, stats) in taken.kinds {
            whole.kind(name).absorb(&stats);
        }
    }
}

/// This process's threads' CPU time so far, in seconds, by name.
fn thread_seconds() -> BTreeMap<String, f64> {
    // SAFETY: `sysconf` reads a constant.
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) }.max(1) as f64;
    let mut threads = BTreeMap::new();
    let Ok(tasks) = std::fs::read_dir("/proc/self/task") else {
        return threads;
    };
    for task in tasks.flatten() {
        let Ok(stat) = std::fs::read_to_string(task.path().join("stat")) else {
            continue;
        };
        // `pid (comm) state ...`: utime and stime the 14th and 15th fields.
        let (Some(open), Some(close)) = (stat.find('('), stat.rfind(')')) else {
            continue;
        };
        let name = stat[open + 1..close].to_string();
        let fields: Vec<&str> = stat[close + 2..].split(' ').collect();
        let used: f64 = fields
            .get(11..13)
            .map(|times| {
                times
                    .iter()
                    .filter_map(|time| time.parse::<f64>().ok())
                    .sum()
            })
            .unwrap_or(0.0);
        *threads.entry(name).or_default() += used / ticks;
    }
    threads
}

/// This process's CPU time so far, user and system, in seconds.
fn cpu_seconds() -> f64 {
    // SAFETY: `getrusage` writes the struct it is given.
    let usage = unsafe {
        let mut usage = std::mem::zeroed::<libc::rusage>();
        libc::getrusage(libc::RUSAGE_SELF, &mut usage);
        usage
    };
    let seconds = |time: libc::timeval| time.tv_sec as f64 + time.tv_usec as f64 / 1e6;
    seconds(usage.ru_utime) + seconds(usage.ru_stime)
}

/// The mix as sent against its target: each kind's share, and the
/// transfers' cross-shard share.
fn mix_line(plan: &Plan, whole: &BTreeMap<&str, KindStats>) -> serde_json::Value {
    let sent = |name: &str| whole.get(name).map_or(0, |stats| stats.sent);
    let total: u64 = Kind::MIX.iter().map(|kind| sent(kind.name())).sum();
    let mut kinds = serde_json::Map::new();
    let mut worst: f64 = 0.0;
    for kind in Kind::MIX {
        let target = plan.model.shares.of(kind);
        let share = sent(kind.name()) as f64 / total.max(1) as f64;
        worst = worst.max((share - target).abs());
        kinds.insert(
            kind.name().into(),
            serde_json::json!({ "target": target, "sent": share }),
        );
    }
    let transfers = sent("transfer");
    let cross = whole.get("transfer").map_or(0, |stats| stats.cross);
    let cross_share = cross as f64 / transfers.max(1) as f64;
    worst = worst.max((cross_share - plan.model.cross).abs());
    serde_json::json!({
        "kinds": kinds,
        "cross": { "target": plan.model.cross, "sent": cross_share },
        "worst_error": worst,
    })
}

/// What the plan's agents are, read from the nodes.
fn agents(plan: &Plan, targets: &[Target]) -> Result<Vec<Agent>, String> {
    plan.shards
        .iter()
        .chain(&plan.identity)
        .map(|placed| {
            let agent = AgentId(placed.agent);
            let mut last = String::from("no replica answered");
            for replica in &placed.replicas {
                match vos_node::client::agent_info(&targets[usize::from(*replica) - 1], agent) {
                    Ok(Some(info)) => {
                        return Ok(Agent {
                            id: agent,
                            identity: vos_node::identity(&info.record),
                            replicas: placed
                                .replicas
                                .iter()
                                .map(|node| usize::from(*node) - 1)
                                .collect(),
                            paths: ["calls", "queries", "workflows"]
                                .map(|kind| format!("/agents/{}/{kind}", agent.0)),
                        });
                    }
                    Ok(None) => last = format!("agent {}: unknown to node {replica}", agent.0),
                    Err(error) => last = format!("agent {}: {error}", agent.0),
                }
            }
            Err(last)
        })
        .collect()
}

fn methods(plan: &Plan, targets: &[Target]) -> Result<Methods, String> {
    let first = plan.shards.first().ok_or("no ledger shards")?;
    let schema = vos_node::client::schema(
        &targets[usize::from(first.replicas[0]) - 1],
        AgentId(first.agent),
        InstanceId(first.instance),
    )
    .map_err(|error| error.to_string())?
    .ok_or("nothing installed in the first shard")?;
    let id = |name: &str| {
        schema
            .method_id(name)
            .ok_or_else(|| format!("the shard actor has no method {name}"))
    };
    Ok(Methods {
        transfer: id("transfer")?,
        balance: id("balance")?,
        tally: id("tally")?,
        holds_at_cut: id("holds_at_cut")?,
        set_identity: id("set_identity")?,
    })
}

/// Run this driver's share of `plan`, writing its lines to `out`: a line
/// a kind every interval, then the totals and the mix as sent.
pub fn run_local(plan: &Plan, out: &Path) -> Result<(), String> {
    plan.model.validate(plan.shards.len())?;
    let targets = plan
        .nodes
        .iter()
        .map(target)
        .collect::<Result<Vec<_>, _>>()?;
    let agents = agents(plan, &targets)?;
    let methods = methods(plan, &targets)?;
    let leaders: Vec<usize> = plan
        .shards
        .iter()
        .chain(&plan.identity)
        .map(|placed| usize::from(placed.leader.unwrap_or(placed.replicas[0])) - 1)
        .collect();
    let users = Users::new(plan.model.seed, plan.model.users, plan.shards.len());
    let shared = Arc::new(Shared {
        identity_agent: plan.identity.as_ref().map(|_| plan.shards.len()),
        agents,
        instance: InstanceId(plan.shards[0].instance),
        methods,
        seed: plan.model.seed,
        sessions: Mutex::new(HashMap::new()),
        offset_ms: AtomicI64::new(0),
    });
    let mut model = plan.model.clone();
    if shared.identity_agent.is_none() {
        model.identity_hz = 0.0;
    }
    let pools = targets
        .iter()
        .map(Pool::new)
        .collect::<Result<Vec<_>, _>>()?;
    let mut file =
        std::fs::File::create(out).map_err(|error| format!("{}: {error}", out.display()))?;
    let secs = plan.secs as f64;
    let (sender, receiver) = smol::channel::unbounded::<Op>();
    // The load starts once the sending thread opened its first connections.
    let (started, starting) = std::sync::mpsc::channel::<Instant>();
    let (ready, planned_ready) = std::sync::mpsc::channel::<()>();
    std::thread::scope(|scope| {
        let planner = {
            let shared = Arc::clone(&shared);
            let (users, model) = (&users, &model);
            let (driver, drivers) = (plan.driver, plan.drivers);
            std::thread::Builder::new()
                .name("plan".into())
                .spawn_scoped(scope, move || {
                    // The users active at the start, their keys derived
                    // before it.
                    let mut planned = load::Plan::new(model, users, driver, drivers);
                    for user in planned.fill() {
                        shared.open(user);
                    }
                    let _ = ready.send(());
                    let Ok(start) = starting.recv() else { return };
                    for planned in planned {
                        if planned.t >= secs {
                            break;
                        }
                        let due = start + Duration::from_secs_f64(planned.t);
                        let ahead = due.saturating_duration_since(Instant::now());
                        // Asleep in stretches, not before every operation.
                        if ahead > LOOKAHEAD + PLAN_NAP {
                            std::thread::sleep(ahead - LOOKAHEAD);
                        }
                        let op = shared.operation(&planned, users, due);
                        if sender.send_blocking(op).is_err() {
                            break;
                        }
                    }
                })
                .expect("the planning thread")
        };
        let ex: &'static LocalExecutor<'static> = Box::leak(Box::new(LocalExecutor::new()));
        let engine = Rc::new(Engine {
            shared: Arc::clone(&shared),
            pools,
            leaders: RefCell::new(leaders),
            stats: RefCell::new(Stats::default()),
            whole: RefCell::new(Stats::default()),
            inflight: Cell::new(0),
            ex,
            window: plan.window,
            probe: plan.probe,
        });
        let every = Duration::from_secs(plan.every_s.max(1));
        let drain = Duration::from_millis(plan.drain_ms());
        let mut cpu_before = 0.0;
        let mut load_cpu = 0.0;
        smol::block_on(ex.run(async {
            let warming: Vec<_> = (0..engine.pools.len())
                .flat_map(|node| (0..WARM).map(move |_| node))
                .map(|node| {
                    let engine = Rc::clone(&engine);
                    ex.spawn(async move { engine.pools[node].warm().await })
                })
                .collect();
            for warm in warming {
                warm.await;
            }
            let _ = planned_ready.recv();
            // Signed ahead from now: the first operations a little later.
            let _ = started.send(Instant::now() + LOOKAHEAD);
            cpu_before = cpu_seconds();
            let reporter = {
                let engine = Rc::clone(&engine);
                let file = &mut file;
                async move {
                    let mut last = Instant::now();
                    loop {
                        Timer::after(every).await;
                        engine.flush(file, last.elapsed().as_secs_f64());
                        last = Instant::now();
                    }
                }
            };
            let reaper = {
                let engine = Rc::clone(&engine);
                async move {
                    loop {
                        Timer::after(REAP).await;
                        for pool in &engine.pools {
                            pool.reap();
                        }
                    }
                }
            };
            let reporter = smol::future::or(reporter, reaper);
            let load = async {
                while let Ok(op) = receiver.recv().await {
                    if op.due > Instant::now() + EARLY {
                        Timer::at(op.due).await;
                    }
                    engine.dispatch(op);
                }
                load_cpu = cpu_seconds() - cpu_before;
                // The load is sent: its answers, and the reads waiting for
                // a cut's close, within the drain.
                let ended = Instant::now();
                while engine.inflight.get() > 0 && ended.elapsed() < drain {
                    Timer::after(Duration::from_millis(100)).await;
                }
            };
            smol::future::or(load, reporter).await;
        }));
        let _ = planner.join();
        engine.flush(&mut file, 0.0);
        let whole = std::mem::take(&mut *engine.whole.borrow_mut());
        let t_ms = wall_ms();
        for name in REPORTED {
            if let Some(stats) = whole.kinds.get(name) {
                let _ = writeln!(file, "{}", stats.line(t_ms, secs, name, true));
            }
        }
        let mut total = whole.mix().line(t_ms, secs, "all", true);
        total["cpu_s"] = (cpu_seconds() - cpu_before).into();
        // The CPU of the load's span, in cores: the driver's cost at its
        // rate.
        total["load_cores"] = (load_cpu / secs.max(1.0)).into();
        total["threads_cpu_s"] = serde_json::json!(thread_seconds());
        total["unanswered"] = engine.inflight.get().into();
        total["active_users"] = load::Plan::new(&model, &users, plan.driver, plan.drivers)
            .slots()
            .into();
        total["mix"] = mix_line(plan, &whole.kinds);
        writeln!(file, "{total}").map_err(|error| error.to_string())
    })
}

#[cfg(test)]
mod tests {
    use super::{Fate, fate, refusal};
    use vos_wire::Encode;
    use vos_wire::abi::{AttestError, Failure, Refusal};
    use vos_wire::ingress::{Rejection, Response, WorkflowStatus};
    use vos_wire::result::Outcome;

    #[test]
    fn a_refusal_is_named_by_its_variant_and_the_inner_one() {
        let named = |answer: Response| refusal(&Ok(answer));
        assert_eq!(named(Response::Busy), "Busy");
        assert_eq!(named(Response::NotLeader { leader: None }), "NotLeader");
        assert_eq!(
            named(Response::Rejected(Rejection::Gap { expected: 3 })),
            "Rejected(Gap)"
        );
        assert_eq!(
            named(Response::Refused(Refusal::SessionsFull)),
            "Refused(SessionsFull)"
        );
        let closed = Outcome::Failed {
            code: Failure::Handler,
            detail: AttestError::NotClosed.encode(),
        };
        assert_eq!(
            named(Response::Workflow {
                status: WorkflowStatus::Ended(closed),
                at: 1
            }),
            "Failed(Handler: NotClosed)"
        );
        assert_eq!(
            named(Response::Workflow {
                status: WorkflowStatus::Running,
                at: 1
            }),
            "Workflow(Running)"
        );
        assert_eq!(refusal(&Err("timed out".into())), "client: timed out");
    }

    #[test]
    fn a_call_refused_before_it_ran_gives_its_sequence_to_the_next() {
        let of = |answer: Response| fate(&Ok(answer));
        assert_eq!(
            of(Response::Ran {
                outcome: Outcome::Done(vec![]),
                at: 9
            }),
            Fate::Ran(9)
        );
        assert_eq!(of(Response::Busy), Fate::NeverRan);
        assert_eq!(of(Response::Refused(Refusal::SessionsFull)), Fate::NeverRan);
        assert_eq!(of(Response::TimedOut), Fate::Renew);
        assert_eq!(
            of(Response::Rejected(Rejection::StaleSession { now: 1 })),
            Fate::Renew
        );
        assert_eq!(fate(&Err("reset".into())), Fate::Renew);
    }
}
