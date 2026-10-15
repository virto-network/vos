//! A client of the model: its requests, each resent until answered, in
//! sessions it starts as it goes, and its reads.

mod reads;
pub(crate) mod tours;

use std::collections::BTreeMap;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signer, SigningKey};
use vos_node::client::{ClientError, post_within};
use vos_wire::abi::Refusal;
use vos_wire::ids::{AgentId, InstanceId, Session};
use vos_wire::ingress::{Call, Rejection, Response, call_message};
use vos_wire::peer::NodeNumber;
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};

use crate::model::{ANSWERED, ATTEMPT, COUNTER, INBOX, Methods, Mode, Nodes, SECOND};
use crate::rounds;

/// The most sessions a client starts with one key: well within the
/// agent's cap on one key's live sessions, which a long run would reach.
const KEY_SESSIONS: u64 = 32;
const _: () = assert!(KEY_SESSIONS < vos_wire::defaults::MAX_KEY_SESSIONS);

/// POST `body` at node `at`'s `path`, answered within [`ATTEMPT`].
fn post(
    nodes: &dyn Nodes,
    at: NodeNumber,
    path: &str,
    body: &[u8],
) -> Result<Response, ClientError> {
    post_within(nodes.target(at), path, body, ATTEMPT)
}

/// One client at an agent, whose counter instance only it increments, so
/// each answer is the running total of its amounts. It starts a new
/// session every so many requests, so new sessions meet the failures too.
pub struct Client {
    pub number: u8,
    pub agent: AgentId,
    key: SigningKey,
    identity: [u8; 32],
    pub methods: Methods,
    /// The counter it increments.
    pub instance: InstanceId,
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
    /// The next client's agent, which its forwards go to.
    next: std::sync::OnceLock<AgentId>,
    /// The highest request it has started to send.
    sent: AtomicU64,
    /// The requests answered: through a prefix, and those above it.
    acked: Mutex<Acked>,
    /// A touring client's tours: each request starts one, at the rounds
    /// actor, asking the next agent.
    touring: Option<tours::Touring>,
}

/// A session from its first request on, timed with the nodes' clock
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
    above: BTreeMap<u64, u64>,
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
    /// Client `number` at `agent`, whose identity is `identity`. A
    /// forwarding client increments [`COUNTER`] and sends every fifth
    /// request's amount to the next agent's [`INBOX`]; another increments
    /// [`SECOND`]. Each starts a session every `rotate` requests, a
    /// multiple of four.
    pub fn new(
        number: u8,
        agent: AgentId,
        identity: [u8; 32],
        methods: Methods,
        forwarding: bool,
        rotate: u64,
    ) -> Self {
        assert!(rotate > 0 && rotate.is_multiple_of(4));
        Self {
            number,
            agent,
            key: SigningKey::from_bytes(&[number; 32]),
            identity,
            methods,
            instance: if forwarding { COUNTER } else { SECOND },
            forwarding,
            rotate,
            sessions: Mutex::new(Vec::new()),
            names: AtomicU64::new(0),
            idle: AtomicBool::new(false),
            calling: Mutex::new(1),
            next: std::sync::OnceLock::new(),
            sent: AtomicU64::new(0),
            acked: Mutex::new(Acked::default()),
            touring: None,
        }
    }

    /// Client `number` at `agent`, each of whose requests starts a tour of
    /// the next agent at [`rounds::ROUNDS`], which it reads to its end
    /// before its next; `methods` are the counter's, which the tours ask
    /// and tell. It starts a session every `rotate` requests.
    pub fn touring(
        number: u8,
        agent: AgentId,
        identity: [u8; 32],
        methods: Methods,
        tours: rounds::TourMethods,
        rotate: u64,
    ) -> Self {
        Self {
            instance: rounds::ROUNDS,
            touring: Some(tours::Touring::new(tours)),
            ..Self::new(number, agent, identity, methods, false, rotate)
        }
    }

    /// The agent this client's forwards go to.
    pub fn forward_to(&self, agent: AgentId) {
        self.next.set(agent).expect("one next agent");
    }

    pub fn next_agent(&self) -> Option<AgentId> {
        self.next.get().copied()
    }

    pub fn forwarding(&self) -> bool {
        self.forwarding
    }

    /// The highest request it has started to send.
    pub fn sent(&self) -> u64 {
        self.sent.load(Ordering::SeqCst)
    }

    /// Whether it stopped for a pause, with every request answered.
    pub fn idle(&self) -> bool {
        self.idle.load(Ordering::SeqCst)
    }

    fn amount(&self, request: u64) -> u64 {
        request * 1000 + u64::from(self.number)
    }

    /// Whether request `request` forwards its amount to the next agent's
    /// inbox, rather than incrementing this client's counter.
    fn forwards(&self, request: u64) -> bool {
        self.forwarding && request.is_multiple_of(5)
    }

    /// How many of requests 1 through `request` forward.
    pub fn forwards_through(&self, request: u64) -> u64 {
        if self.forwarding { request / 5 } else { 0 }
    }

    /// The counter after requests 1 through `request`.
    pub fn total(&self, request: u64) -> u64 {
        (1..=request)
            .filter(|request| !self.forwards(*request))
            .map(|request| self.amount(request))
            .sum()
    }

    /// Whether `value` is the counter after requests 1 through some
    /// request up to `sent`.
    fn is_total_prefix(&self, sent: u64, value: u64) -> bool {
        let mut total = 0;
        (0..=sent).any(|request| {
            if request > 0 && !self.forwards(request) {
                total += self.amount(request);
            }
            total == value
        })
    }

    /// Whether `value` is the next agent's inbox after this client's
    /// requests 1 through some request up to `sent`.
    fn is_forwarded_prefix(&self, sent: u64, value: u64) -> bool {
        let mut total = 0;
        (0..=sent).any(|request| {
            if request > 0 && self.forwards(request) {
                total += self.amount(request);
            }
            total == value
        })
    }

    /// The next agent's inbox after this client's requests 1 through
    /// `request` applied there.
    pub fn forwarded(&self, request: u64) -> u64 {
        (1..=request)
            .filter(|request| self.forwards(*request))
            .map(|request| self.amount(request))
            .sum()
    }

    /// A new session from request `first` on, timed by the nodes' clock.
    /// A client that starts them often takes a fresh key for each, as
    /// one without an identity may; the other takes a fresh one every
    /// [`KEY_SESSIONS`]: one key's sessions are capped.
    fn start(&self, nodes: &dyn Nodes, first: u64) -> Timed {
        let count = self.names.fetch_add(1, Ordering::SeqCst);
        let mut name = [0u8; 16];
        name[0] = self.number;
        name[8..].copy_from_slice(&count.to_be_bytes());
        let mut secret = self.key.to_bytes();
        let fresh = if self.forwarding {
            count / KEY_SESSIONS
        } else {
            count
        };
        if fresh > 0 || !self.forwarding {
            secret[1..9].copy_from_slice(&fresh.to_be_bytes());
        }
        let offset = nodes.offset();
        nodes.log().saw("session started");
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
    fn session(&self, nodes: &dyn Nodes, request: u64) -> (Timed, u64) {
        let mut sessions = self.sessions.lock().unwrap();
        loop {
            let next = sessions.last().map_or(1, |last| last.first + self.rotate);
            if !sessions.is_empty() && request + self.rotate < next {
                break;
            }
            sessions.push(self.start(nodes, next));
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
    fn rotate_at(&self, nodes: &dyn Nodes, first: u64) {
        let timed = self.start(nodes, first);
        let mut sessions = self.sessions.lock().unwrap();
        sessions.retain(|ahead| ahead.first < first);
        sessions.push(timed);
    }

    /// Time `stale` again, as a new session from the same request: false
    /// when another of its requests already did.
    fn retime(&self, nodes: &dyn Nodes, stale: &Session) -> bool {
        let mut sessions = self.sessions.lock().unwrap();
        let Some(at) = sessions.iter().position(|timed| timed.session == *stale) else {
            return false;
        };
        sessions[at] = self.start(nodes, sessions[at].first);
        true
    }

    fn body(&self, timed: &Timed, sequence: u64, request: u64) -> Vec<u8> {
        let session = &timed.session;
        let (method, arguments) = if let Some(touring) = &self.touring {
            let next = self.next.get().expect("the next agent");
            let tour = rounds::tour(*next, request);
            (touring.methods.tour, tour.arguments())
        } else if self.forwards(request) {
            let next = self.next.get().expect("the next agent");
            (
                self.methods.forward,
                (next.0, INBOX.0, self.amount(request)).encode(),
            )
        } else {
            (self.methods.increment, self.amount(request).encode())
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
    fn send(&self, nodes: &dyn Nodes, mode: Mode, request: u64) {
        let path = format!("/agents/{}/calls", self.agent.0);
        let until = Instant::now() + ANSWERED;
        let count = nodes.count();
        self.sent.fetch_max(request, Ordering::SeqCst);
        // Requests take turns at every node, followers forwarding to the
        // leader and other nodes naming the replicas.
        *self.calling.lock().unwrap() =
            1 + ((request + u64::from(self.number)) % u64::from(count)) as NodeNumber;
        let mut tries = 0usize;
        loop {
            assert!(
                Instant::now() < until,
                "client {}: request {request} was never answered\n{}",
                self.number,
                nodes.report(self.agent)
            );
            tries += 1;
            // Its session may have been timed again since the last try.
            let (timed, sequence) = self.session(nodes, request);
            let session = timed.session;
            let body = self.body(&timed, sequence, request);
            let at = *self.calling.lock().unwrap();
            let starts = nodes.starts(at);
            let next = |client: &Self| {
                *client.calling.lock().unwrap() = at % count + 1;
            };
            let offset = nodes.offset();
            match post(nodes, at, &path, &body) {
                Ok(Response::Ran {
                    outcome,
                    at: answered_at,
                }) => {
                    match outcome {
                        Outcome::Started(workflow) if self.touring.is_some() => {
                            self.tour_started(request, workflow, answered_at, &timed);
                        }
                        Outcome::Done(reply) if self.touring.is_none() => {
                            let total = u64::decode(&reply).unwrap().0;
                            // A forward answers its amount, an increment the
                            // total.
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
                        }
                        other => panic!(
                            "client {}: request {request} answered by node {at}: {other:?}",
                            self.number
                        ),
                    }
                    nodes.answered(at, starts, self.agent, &session, sequence);
                    self.acked.lock().unwrap().answered(request, answered_at);
                    nodes.log().event(format!(
                        "client {} request {request} (sequence {sequence}) answered by {at} at {answered_at}",
                        self.number,
                    ));
                    nodes.log().saw(match nodes.leader(self.agent) {
                        Some(leader) if leader == at => "answered by the leader",
                        Some(_) => "answered by a follower",
                        None => "answered",
                    });
                    return;
                }
                Ok(Response::NotLeader {
                    leader: Some(leader),
                }) => {
                    nodes.log().saw("redirect");
                    match nodes.number_at(&leader.address) {
                        Some(leader) => *self.calling.lock().unwrap() = leader,
                        None => panic!("a redirect to {}", leader.address),
                    }
                }
                // A node that does not replicate the agent names those that
                // do: one of them, a different one each try.
                Ok(Response::Elsewhere { replicas }) => {
                    nodes.log().saw("elsewhere");
                    let named: Vec<NodeNumber> = replicas
                        .iter()
                        .filter_map(|contact| nodes.number_at(&contact.address))
                        .collect();
                    if named.is_empty() {
                        next(self);
                    } else {
                        *self.calling.lock().unwrap() = named[tries % named.len()];
                    }
                }
                Ok(
                    Response::NotLeader { leader: None } | Response::Stopped | Response::TimedOut,
                )
                | Err(_) => {
                    nodes.log().saw("resend elsewhere");
                    next(self);
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(Response::Busy | Response::Unavailable) => {
                    nodes.log().saw("resend");
                    std::thread::sleep(Duration::from_millis(10));
                }
                // Sent on its own connection, a request may pass its
                // predecessor: it goes again once that one is in.
                Ok(Response::Rejected(Rejection::Gap { expected }))
                    if matches!(mode, Mode::Pipelined) && expected < sequence =>
                {
                    nodes.log().saw("gap");
                    std::thread::sleep(Duration::from_millis(5));
                }
                // Timed before every clock jumped, and sent after: no
                // leader can create it now, so none of its copies runs.
                // Its first request times it again; the others follow.
                Ok(
                    stale @ (Response::Rejected(Rejection::StaleSession { .. })
                    | Response::Refused(Refusal::StaleSession)),
                ) if timed.offset < offset => {
                    nodes.log().event(format!(
                        "client {} request {request} (sequence {sequence}) at {at}: {stale:?}",
                        self.number
                    ));
                    if sequence == 1 && self.retime(nodes, &session) {
                        nodes.log().saw("session timed again");
                    } else {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                }
                // Sent before the clocks jumped, or while they move: again,
                // unchanged. Whether they move is read first: they stop
                // moving only once the offset has moved.
                Ok(
                    Response::Rejected(Rejection::StaleSession { .. })
                    | Response::Refused(Refusal::StaleSession),
                ) if nodes.clocks_moving() || nodes.offset() > offset => {
                    nodes.log().saw("stale session across the jump");
                    std::thread::sleep(Duration::from_millis(10));
                }
                Ok(other) => panic!(
                    "client {}: request {request} (sequence {sequence}) at node {at}: {other:?}\n{}",
                    self.number,
                    nodes.report(self.agent),
                ),
            }
        }
    }

    /// Send requests until `done`: how many were sent, each answered.
    pub fn run(&self, nodes: &dyn Nodes, mode: Mode, done: &AtomicBool) -> u64 {
        let mut sent = 0;
        while !done.load(Ordering::SeqCst) {
            // Paused with every request answered; then a new session.
            if nodes.paused() {
                self.idle.store(true, Ordering::SeqCst);
                while nodes.paused() {
                    std::thread::sleep(Duration::from_millis(5));
                }
                self.idle.store(false, Ordering::SeqCst);
                self.rotate_at(nodes, sent + 1);
                continue;
            }
            match mode {
                // A tour at a time: each one's result is known before it
                // starts.
                _ if self.touring.is_some() => {
                    sent += 1;
                    self.send(nodes, Mode::OneAtATime, sent);
                    self.finish_tour(nodes, sent);
                }
                Mode::OneAtATime => {
                    sent += 1;
                    self.send(nodes, mode, sent);
                }
                Mode::Pipelined => {
                    std::thread::scope(|scope| {
                        for sequence in sent + 1..=sent + 4 {
                            scope.spawn(move || self.send(nodes, mode, sequence));
                            std::thread::sleep(Duration::from_millis(1));
                        }
                    });
                    sent += 4;
                }
            }
        }
        sent
    }

    /// While the client is paused, with every request answered: two
    /// requests signed in its session, the last it ran and the next, which
    /// it never sent.
    pub fn capture(&self, nodes: &dyn Nodes) -> Vec<Vec<u8>> {
        assert!(self.idle(), "a client captures while paused");
        let sent = self.sent();
        if sent == 0 {
            return Vec::new();
        }
        let (timed, sequence) = self.session(nodes, sent);
        vec![
            self.body(&timed, sequence, sent),
            self.body(&timed, sequence + 1, sent + 1),
        ]
    }

    /// Send `captured`, requests of sessions every node has collected, to
    /// every node: none may run, the run one answered from no window.
    pub fn replay(&self, nodes: &dyn Nodes, captured: &[Vec<u8>]) {
        let path = format!("/agents/{}/calls", self.agent.0);
        for body in captured {
            for number in 1..=nodes.count() {
                let until = Instant::now() + ANSWERED;
                loop {
                    assert!(Instant::now() < until, "a replay was never answered");
                    match post(nodes, number, &path, body) {
                        Ok(
                            Response::Rejected(Rejection::StaleSession { .. })
                            | Response::TimedOut
                            | Response::Elsewhere { .. },
                        ) => break,
                        Ok(
                            Response::Stopped
                            | Response::Unavailable
                            | Response::Busy
                            | Response::NotLeader { .. },
                        )
                        | Err(_) => std::thread::sleep(Duration::from_millis(10)),
                        Ok(other) => panic!(
                            "client {}: a captured request at node {number}: {other:?}",
                            self.number
                        ),
                    }
                }
            }
        }
    }
}
