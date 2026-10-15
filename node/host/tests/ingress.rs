//! The node's HTTP ingress, end to end on the default agent and the
//! counter actor: client-named sessions, signed calls in their sequences,
//! the reply window, expiry, the operator's token, and workflows started
//! by clients and read by their owners.

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use std::collections::HashMap;

use vos_checker::calls::done;
use vos_checker::hooks::{FailNextSync, Gate};
use vos_checker::programs::Programs;
use vos_checker::spaces::IN_PROCESS_WAIT;
use vos_checker::workflows::{ASKED, ROUNDS, Rounds, TOLD, Tour, TourMethods, signed_read};
use vos_node::client::{self, Client, ClientError, Operator, Target};
use vos_node::{ADMIN_TOKEN, Config, Hooks, Node};
use vos_wire::abi::Refusal;
use vos_wire::batch::{Batch, Input};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Session, WorkflowId};
use vos_wire::ingress::{
    Call, Consistency, Install, MAX_WORKFLOW_WAIT_MS, Rejection, Response, WorkflowRead,
    WorkflowStatus, workflow_read_horizon,
};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};
use vos_wire::{defaults, expiry, keys};

const COUNTER: InstanceId = InstanceId(1);

/// A node serving ingress, with one agent running the counter.
struct Served {
    node: Node,
    base: String,
    target: Target,
    clock: Arc<AtomicU64>,
    token: String,
    agent: AgentId,
    increment: MethodId,
    value: MethodId,
    _dir: tempfile::TempDir,
}

impl Served {
    fn start(hooks: Arc<dyn Hooks>) -> Self {
        Self::start_with(hooks, |_| {})
    }

    /// [`Served::start`] with its node's config as `configure` leaves it.
    fn start_with(hooks: Arc<dyn Hooks>, configure: impl FnOnce(&mut Config)) -> Self {
        let programs = Programs::load();
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(AtomicU64::new(vos_node::wall_clock()));
        let mut config = Config::new(programs.agent.clone());
        config.executors = 2;
        config.hooks = hooks;
        config.clock = {
            let clock = Arc::clone(&clock);
            Arc::new(move || clock.load(Ordering::SeqCst))
        };
        configure(&mut config);
        let node = Node::open(dir.path(), config).unwrap();
        let address = node.serve("127.0.0.1:0".parse().unwrap()).unwrap();
        let base = format!("http://{address}");
        let target = Target::loopback(&base).unwrap();
        let token = std::fs::read_to_string(dir.path().join(ADMIN_TOKEN)).unwrap();
        let operator = Operator::new(&target, &token);
        let Ok(Response::Created(agent)) = operator.create_agent(Vec::new()) else {
            panic!("an agent")
        };
        let install = Install {
            instance: COUNTER,
            elf: programs.counter_elf.clone(),
            roles: Vec::new(),
        };
        let installed = operator.install(agent, &install).unwrap();
        assert!(
            matches!(
                installed,
                Response::Ran {
                    outcome: Outcome::Done(_),
                    ..
                }
            ),
            "{installed:?}"
        );
        let schema = vos_node::client::schema(&target, agent, COUNTER)
            .unwrap()
            .expect("an installed schema");
        Self {
            node,
            base,
            target,
            clock,
            token,
            agent,
            increment: schema.method_id("increment").unwrap(),
            value: schema.method_id("value").unwrap(),
            _dir: dir,
        }
    }

    fn now(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }

    fn client(&self, seed: u8) -> Client {
        Client::new(&self.target, SigningKey::from_bytes(&[seed; 32]))
    }

    /// An increment through the client's own sequence.
    fn call(&self, client: &mut Client, by: u64) -> Response {
        client
            .call(self.agent, COUNTER, self.increment, &by.encode())
            .unwrap()
    }

    fn increment(&self, client: &Client, sequence: u64, by: u64) -> Response {
        client
            .call_at(self.agent, sequence, COUNTER, self.increment, &by.encode())
            .unwrap()
    }

    fn value(&self, client: &Client) -> u64 {
        let answer = client
            .query(
                self.agent,
                COUNTER,
                self.value,
                &[],
                vos_node::wall_clock() + 10_000,
            )
            .unwrap();
        done(answer)
    }

    /// Whether the agent holds `session`.
    fn holds(&self, session: &Session) -> bool {
        self.node
            .store()
            .snapshot()
            .get(self.agent, &keys::session_index(session))
            .unwrap()
            .is_some()
    }

    /// Move the node's clock to the start of a bucket of the expiry
    /// index, so a session last active then expires a bucket before its
    /// row is due.
    fn at_bucket_start(&self) -> u64 {
        let start = (self.now() / defaults::SESSION_BUCKET_MS + 1) * defaults::SESSION_BUCKET_MS;
        self.clock.store(start, Ordering::SeqCst);
        start
    }

    fn post(&self, path: &str, body: &[u8]) -> Response {
        let (_, body) = vos_node::client::post(&self.target, path, body).unwrap();
        Response::decode(&body).unwrap().0
    }
}

#[track_caller]
fn wait_until(what: &str, done: impl FnMut() -> bool) {
    vos_checker::wait_until(what, IN_PROCESS_WAIT, done);
}

#[test]
fn calls_follow_their_session_sequence() {
    let served = Served::start(Arc::new(vos_node::NoHooks));
    let client = served.client(1);
    assert_eq!(done(served.increment(&client, 1, 5)), 5);
    assert_eq!(
        done(served.increment(&client, 1, 5)),
        5,
        "a duplicate, from the window"
    );
    assert_eq!(served.value(&client), 5, "applied once");
    assert_eq!(
        served.increment(&client, 3, 1),
        Response::Rejected(Rejection::Gap { expected: 2 })
    );
    assert_eq!(
        served.increment(&client, 0, 1),
        Response::Rejected(Rejection::Gap { expected: 2 })
    );
    assert_eq!(
        served.increment(&client, 2 + defaults::REPLY_WINDOW, 1),
        Response::Rejected(Rejection::Ahead)
    );
    for sequence in 2..=defaults::REPLY_WINDOW + 1 {
        done(served.increment(&client, sequence, 1));
    }
    assert_eq!(
        served.increment(&client, 1, 5),
        Response::Rejected(Rejection::TooOld)
    );
    assert_eq!(
        done(served.increment(&client, 2, 1)),
        6,
        "the oldest reply kept"
    );
    // Sequences are per (session, agent): another session starts at 1.
    let other = served.client(2);
    assert_eq!(done(served.increment(&other, 1, 1)), 70);
}

#[test]
fn signatures_sessions_and_staleness_are_checked() {
    let served = Served::start(Arc::new(vos_node::NoHooks));
    let client = served.client(1);
    let agent = served.agent;
    let path = format!("/agents/{}/calls", agent.0);

    let mut body = client
        .call_body(agent, 1, COUNTER, served.increment, &5u64.encode())
        .unwrap();
    let (mut call, _) = Call::decode(&body).unwrap();
    call.arguments = 6u64.encode();
    assert_eq!(
        served.post(&path, &call.encode()),
        Response::Rejected(Rejection::BadSignature),
        "arguments changed after signing"
    );
    // The session is in the signed bytes, and its key signs.
    call = Call::decode(&body).unwrap().0;
    call.session.name[0] ^= 1;
    assert_eq!(
        served.post(&path, &call.encode()),
        Response::Rejected(Rejection::BadSignature)
    );
    call = Call::decode(&body).unwrap().0;
    call.session.key = SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes();
    assert_eq!(
        served.post(&path, &call.encode()),
        Response::Rejected(Rejection::BadSignature)
    );
    // Signed for one agent, sent to another: the agent's identity is in
    // the signed bytes.
    let operator = Operator::new(&served.target, &served.token);
    let Ok(Response::Created(other)) = operator.create_agent(Vec::new()) else {
        panic!("another agent")
    };
    let elsewhere = format!("/agents/{}/calls", other.0);
    assert_eq!(
        served.post(&elsewhere, &body),
        Response::Rejected(Rejection::BadSignature)
    );
    assert_eq!(
        served.post(&format!("/agents/{}/calls", other.0 + 1), &body),
        Response::NoAgent
    );
    body.truncate(body.len() - 1);
    assert_eq!(
        served.post(&path, &body),
        Response::Rejected(Rejection::Malformed)
    );

    // A new session must start near the agent's time, which the refusal
    // gives.
    let stale = |t0: u64| {
        let mut call = Call::decode(
            &client
                .call_body(agent, 1, COUNTER, served.increment, &1u64.encode())
                .unwrap(),
        )
        .unwrap()
        .0;
        call.session.t0 = t0;
        let key = SigningKey::from_bytes(&[1; 32]);
        let identity = client.identity(agent).unwrap();
        let message = vos_wire::ingress::call_message(
            &identity,
            &call.session,
            call.sequence,
            call.instance,
            call.method,
            &call.arguments,
        );
        call.signature = ed25519_dalek::Signer::sign(&key, &message).to_bytes();
        served.post(&path, &call.encode())
    };
    let now = served.now();
    for t0 in [
        now - defaults::SESSION_SKEW_MS - 1,
        now + defaults::SESSION_SKEW_MS + 1,
    ] {
        assert_eq!(
            stale(t0),
            Response::Rejected(Rejection::StaleSession { now })
        );
    }
    assert_eq!(done(stale(now - defaults::SESSION_SKEW_MS + 1_000)), 1);

    // A query's `not_after` is by the client's clock, moved to the node's
    // time as the client last learned it, and again once refused.
    let now = served.now();
    let query = |not_after| {
        client
            .query(agent, COUNTER, served.value, &[], not_after)
            .unwrap()
    };
    let wall = vos_node::wall_clock();
    assert_eq!(
        query(wall - 3_600_000),
        Response::Rejected(Rejection::StaleQuery { now })
    );
    assert_eq!(
        query(vos_node::wall_clock() + 600_000),
        Response::Rejected(Rejection::StaleQuery { now })
    );
    assert_eq!(done(query(vos_node::wall_clock() + 1_000)), 1);
    // The node's clock ten minutes ahead: refused once, the query goes
    // again at its time.
    served.clock.store(now + 600_000, Ordering::SeqCst);
    assert_eq!(done(query(vos_node::wall_clock() + 60_000)), 1);
}

/// An expired session is refused for good: the client starts another,
/// and when its clock is off the agent's, starts it again at the time the
/// refusal gives.
#[test]
fn an_expired_session_is_refused_and_the_client_starts_another() {
    let served = Served::start(Arc::new(vos_node::NoHooks));
    let mut client = served.client(1);
    assert_eq!(done(served.call(&mut client, 5)), 5);
    let first = client.session(served.agent);
    served
        .clock
        .fetch_add(defaults::SESSION_EXPIRY_MS + 1, Ordering::SeqCst);
    assert_eq!(
        served.increment(&client, 2, 1),
        Response::Refused(Refusal::Expired)
    );
    assert_eq!(done(served.call(&mut client, 1)), 6);
    let renewed = client.session(served.agent);
    assert_ne!(renewed, first);
    assert!(
        renewed.t0.abs_diff(served.now()) <= defaults::SESSION_SKEW_MS,
        "started at the agent's time"
    );
    assert_eq!(client.sessions()[&served.agent].next, 2);
}

/// A call whose answer was lost goes again with its sequence, answered
/// from the window while the agent holds its session, expired or not.
/// Once the session is collected nothing can say whether it ran: the
/// client says so, and never runs it again. A first call in a session
/// never created goes again in a new session once no leader can create
/// the old one, and is lost past the time the old one could have been
/// collected.
#[test]
fn a_call_whose_answer_was_lost_is_answered_once_or_lost() {
    let served = Served::start(Arc::new(vos_node::NoHooks));
    let start = served.at_bucket_start();
    let mut client = served.client(1);
    assert_eq!(done(served.call(&mut client, 1)), 1);
    // The second call runs, and its answer is lost.
    let before = client.sessions();
    assert_eq!(done(served.call(&mut client, 2)), 3);
    let kept = before[&served.agent];
    let session = Session {
        key: SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes(),
        name: kept.name,
        t0: kept.t0,
    };
    let again = |kept: client::Kept| {
        let sessions = HashMap::from([(served.agent, kept)]);
        let mut client = Client::resume(
            &served.target,
            SigningKey::from_bytes(&[1; 32]),
            sessions,
            HashMap::new(),
        );
        client.repeats_unknown(served.agent);
        client.call(served.agent, COUNTER, served.increment, &2u64.encode())
    };

    served
        .clock
        .store(start + defaults::SESSION_EXPIRY_MS + 1, Ordering::SeqCst);
    assert!(served.now() < expiry::due(expiry::bucket(start)));
    assert_eq!(done(again(kept).unwrap()), 3, "from the window");
    assert_eq!(served.value(&client), 3);

    served
        .clock
        .store(expiry::due(expiry::bucket(start)), Ordering::SeqCst);
    wait_until("the idle leader collects the session", || {
        !served.holds(&session)
    });
    assert!(matches!(again(kept), Err(ClientError::Lost)));
    assert_eq!(served.value(&client), 3, "and it did not run again");

    // A session whose first call reached no leader.
    let now = served.now();
    let never = client::Kept {
        name: [7; 16],
        t0: now,
        next: 1,
    };
    served
        .clock
        .store(now + 2 * defaults::SESSION_SKEW_MS, Ordering::SeqCst);
    assert_eq!(
        again(never).unwrap(),
        Response::TimedOut,
        "a leader could still create it"
    );
    served
        .clock
        .store(now + 2 * defaults::SESSION_SKEW_MS + 1, Ordering::SeqCst);
    assert_eq!(done(again(never).unwrap()), 5, "in a new session, once");
    let old = client::Kept {
        name: [8; 16],
        t0: served.now() - defaults::SESSION_EXPIRY_MS,
        next: 1,
    };
    assert!(matches!(again(old), Err(ClientError::Lost)));
    assert_eq!(served.value(&client), 5);
}

/// A batch whose time makes the first expiry row due sweeps first: an
/// expired session is gone once the next call is answered.
#[test]
fn a_busy_leader_sweeps_in_its_batches() {
    let served = Served::start(Arc::new(vos_node::NoHooks));
    let start = served.at_bucket_start();
    let mut first = served.client(1);
    let mut second = served.client(2);
    assert_eq!(done(served.call(&mut first, 1)), 1);
    assert_eq!(done(served.call(&mut second, 1)), 2);
    let held = first.session(served.agent);
    served
        .clock
        .store(expiry::due(expiry::bucket(start)) - 1, Ordering::SeqCst);
    assert_eq!(done(served.call(&mut second, 1)), 3);
    assert!(served.holds(&held), "not due yet");
    served
        .clock
        .store(expiry::due(expiry::bucket(start)), Ordering::SeqCst);
    assert_eq!(done(served.call(&mut second, 1)), 4);
    assert!(!served.holds(&held));
}

#[test]
fn pipelined_requests_recover_their_lost_replies() {
    let served = Served::start(Arc::new(vos_node::NoHooks));
    let client = served.client(1);
    let address: SocketAddr = served.base.trim_start_matches("http://").parse().unwrap();
    let mut stream = TcpStream::connect(address).unwrap();
    for (sequence, by) in [(1u64, 1u64), (2, 2), (3, 3)] {
        let body = client
            .call_body(
                served.agent,
                sequence,
                COUNTER,
                served.increment,
                &by.encode(),
            )
            .unwrap();
        let head = format!(
            "POST /agents/{}/calls HTTP/1.1\r\nHost: node\r\nContent-Length: {}\r\n\r\n",
            served.agent.0,
            body.len()
        );
        stream.write_all(head.as_bytes()).unwrap();
        stream.write_all(&body).unwrap();
    }
    wait_until("all three apply", || served.value(&client) == 6);
    drop(stream);
    let replies: Vec<u64> = [(1u64, 1u64), (2, 2), (3, 3)]
        .into_iter()
        .map(|(sequence, by)| done(served.increment(&client, sequence, by)))
        .collect();
    assert_eq!(replies, [1, 3, 6], "each reply from the window");
    assert_eq!(served.value(&client), 6);
}

#[test]
fn a_duplicate_in_flight_waits_for_its_answer() {
    let gate = Arc::new(Gate::default());
    let served = Arc::new(Served::start(gate.clone()));
    let client = Arc::new(served.client(1));
    let closed = gate.close();
    let reached = gate.reached();
    let first = {
        let (served, client) = (Arc::clone(&served), Arc::clone(&client));
        std::thread::spawn(move || served.increment(&client, 1, 5))
    };
    wait_until("the first is in flight", || gate.reached() > reached);
    let second = {
        let (served, client) = (Arc::clone(&served), Arc::clone(&client));
        std::thread::spawn(move || served.increment(&client, 1, 5))
    };
    std::thread::sleep(Duration::from_millis(100));
    drop(closed);
    assert_eq!(done(first.join().unwrap()), 5);
    assert_eq!(done(second.join().unwrap()), 5);
    assert_eq!(served.value(&client), 5, "applied once");
}

#[test]
fn operator_commands_need_the_token() {
    let served = Served::start(Arc::new(vos_node::NoHooks));
    let stranger = Operator::new(&served.target, &"00".repeat(32));
    assert_eq!(
        stranger.create_agent(Vec::new()).unwrap(),
        Response::Rejected(Rejection::Unauthorized)
    );
    let client = served.client(1);
    assert_eq!(
        stranger
            .grant(served.agent, client.principal(), Some(1))
            .unwrap(),
        Response::Rejected(Rejection::Unauthorized)
    );
    assert_eq!(
        served.node.id(),
        vos_node::client::node_id(&served.target).unwrap()
    );
}

/// A bearer token of 64 bytes that are not 64 hex digits, here multi-byte
/// characters a pair of bytes would split, is refused like any wrong
/// token, more often than the ingress holds connections: each connection's
/// place is given back, and the ingress goes on answering.
#[test]
fn a_token_that_is_not_hex_is_refused_and_frees_its_connection() {
    let connections = 4;
    let served = Served::start_with(Arc::new(vos_node::NoHooks), |config| {
        config.ingress_connections = connections;
    });
    let token = format!("a{}", "€".repeat(21));
    assert_eq!(token.len(), 64);
    let request = format!(
        "GET /stats HTTP/1.1\r\nHost: node\r\nAuthorization: Bearer {token}\r\nConnection: close\r\n\r\n"
    );
    for _ in 0..3 * connections {
        assert_eq!(
            status_line(&served.base, request.as_bytes()),
            "HTTP/1.1 401 Unauthorized"
        );
    }
    let operator = Operator::new(&served.target, &served.token);
    assert!(matches!(operator.stats(), Ok(Response::Stats(_))));
}

/// The operator reads a replica's status, and a stranger cannot. A node
/// of a space of one whose flush fails outside any log write halts, and
/// its status says so.
#[test]
fn the_status_route_reports_a_replica_and_a_halt() {
    let hooks = Arc::new(FailNextSync::default());
    let served = Served::start(hooks.clone());
    let operator = Operator::new(&served.target, &served.token);
    let Ok(Response::Status(status)) = operator.status(served.agent) else {
        panic!("a status")
    };
    assert!(status.leads && !status.halted, "{status:?}");
    assert!(status.applied >= 1 && status.commit >= status.applied);
    assert!(status.last_index >= status.commit);
    let stranger = Operator::new(&served.target, &"00".repeat(32));
    assert_eq!(
        stranger.status(served.agent).unwrap(),
        Response::Rejected(Rejection::Unauthorized)
    );
    assert_eq!(operator.status(AgentId(0xdead)).unwrap(), Response::NoAgent);
    hooks.arm();
    assert!(
        served.node.create_agent().is_err(),
        "the record's flush failed"
    );
    wait_until("the node halts", || {
        matches!(
            operator.status(served.agent),
            Ok(Response::Status(status)) if status.halted
        )
    });
}

#[test]
fn a_node_is_its_public_key_and_never_serves_its_secret() {
    use std::os::unix::fs::PermissionsExt;
    use vos_node::store::Fjall;
    let mode =
        |path: &std::path::Path| std::fs::metadata(path).unwrap().permissions().mode() & 0o777;
    let programs = Programs::load();
    let dir = tempfile::tempdir().unwrap();
    // A new data directory is the owner's alone.
    let data = dir.path().join("new");
    let id = Node::open(&data, Config::new(programs.agent.clone()))
        .unwrap()
        .id();
    assert_eq!(mode(&data), 0o700);
    // A node's directory others could reach is made the owner's alone
    // again.
    std::fs::set_permissions(&data, std::fs::Permissions::from_mode(0o755)).unwrap();
    drop(Node::open(&data, Config::new(programs.agent.clone())).unwrap());
    assert_eq!(mode(&data), 0o700);
    // So is an empty directory others could reach. Any other is refused,
    // and left as it is.
    let empty = dir.path().join("empty");
    std::fs::create_dir(&empty).unwrap();
    std::fs::set_permissions(&empty, std::fs::Permissions::from_mode(0o755)).unwrap();
    drop(Node::open(&empty, Config::new(programs.agent.clone())).unwrap());
    assert_eq!(mode(&empty), 0o700);
    let shared = dir.path().join("shared");
    std::fs::create_dir(&shared).unwrap();
    std::fs::write(shared.join("notes"), b"someone else's").unwrap();
    std::fs::set_permissions(&shared, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert!(Node::open(&shared, Config::new(programs.agent.clone())).is_err());
    assert_eq!(mode(&shared), 0o755);
    let store = Fjall::open(data.join("store")).unwrap();
    let secret = store.node_secret().unwrap().expect("a secret seed");
    drop(store);
    assert_eq!(
        id.0,
        SigningKey::from_bytes(&secret).verifying_key().to_bytes()
    );
    assert_ne!(id.0, secret);
    // The same key on every open.
    let node = Node::open(&data, Config::new(programs.agent)).unwrap();
    assert_eq!(node.id(), id);
}

/// Holds the refine of a batch holding the poisoned arguments at its
/// gate, then fails it, once; and holds commits at theirs.
#[derive(Default)]
struct GatedPoison {
    poison: Vec<u8>,
    armed: AtomicBool,
    refines: Gate,
    commits: Gate,
}

impl Hooks for GatedPoison {
    fn fail_refine(&self, _: AgentId, batch: &Batch) -> bool {
        let poisoned = batch.inputs.iter().any(
            |input| matches!(input, Input::Request(request) if request.arguments == self.poison),
        );
        if !poisoned || !self.armed.load(Ordering::SeqCst) {
            return false;
        }
        self.refines.pass();
        self.armed.swap(false, Ordering::SeqCst)
    }

    fn before_commit(&self) {
        self.commits.pass();
    }
}

/// A request the agent program fails alone is not consumed: the requests
/// queued behind it are gaps, and the client resends from it, even while
/// they are still in flight.
#[test]
fn a_request_not_consumed_is_resent_with_its_sequence() {
    let gate = Arc::new(GatedPoison {
        poison: 1u64.encode(),
        ..GatedPoison::default()
    });
    let served = Arc::new(Served::start(gate.clone()));
    let client = Arc::new(served.client(1));
    let refines = gate.refines.close();
    gate.armed.store(true, Ordering::SeqCst);
    let send = |sequence: u64| {
        let (served, client) = (Arc::clone(&served), Arc::clone(&client));
        std::thread::spawn(move || served.increment(&client, sequence, sequence))
    };
    let first = send(1);
    wait_until("the first is refined", || gate.refines.reached() > 0);
    let second = send(2);
    std::thread::sleep(Duration::from_millis(100));
    let third = send(3);
    std::thread::sleep(Duration::from_millis(100));
    // The batch of 2 and 3 will wait at its commit, so they stay in flight.
    let commits = gate.commits.close();
    let reached = gate.commits.reached();
    drop(refines);
    assert_eq!(first.join().unwrap(), Response::NotConsumed);
    wait_until("2 and 3 reach their commit", || {
        gate.commits.reached() > reached
    });
    // Resent while 2 and 3 are in flight: the lane went back to before 1.
    let resent = send(1);
    std::thread::sleep(Duration::from_millis(100));
    drop(commits);
    assert_eq!(second.join().unwrap(), Response::Refused(Refusal::Sequence));
    assert_eq!(third.join().unwrap(), Response::Refused(Refusal::Sequence));
    assert_eq!(done(resent.join().unwrap()), 1);
    let rest: Vec<u64> = (2..=3)
        .map(|sequence| done(served.increment(&client, sequence, sequence)))
        .collect();
    assert_eq!(rest, [3, 6]);
}

/// The status line a raw request gets.
fn status_line(base: &str, request: &[u8]) -> String {
    let address: SocketAddr = base.trim_start_matches("http://").parse().unwrap();
    let mut stream = TcpStream::connect(address).unwrap();
    stream.write_all(request).unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response)
        .lines()
        .next()
        .unwrap_or_default()
        .to_string()
}

#[test]
fn bodies_past_the_limit_or_without_a_length_are_refused_with_a_reason() {
    let served = Served::start(Arc::new(vos_node::NoHooks));
    let calls = format!("/agents/{}/calls", served.agent.0);
    let large = format!("POST {calls} HTTP/1.1\r\nContent-Length: 10000000\r\n\r\n");
    assert_eq!(
        status_line(&served.base, large.as_bytes()),
        "HTTP/1.1 413 Content Too Large"
    );
    let chunked = format!("POST {calls} HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
    assert_eq!(
        status_line(&served.base, chunked.as_bytes()),
        "HTTP/1.1 411 Length Required"
    );
}

/// The rounds actor at the served agent, its tours asking a second agent's
/// rounds.
struct Tours {
    other: AgentId,
    methods: TourMethods,
}

impl Served {
    /// Install the rounds actor with its workflows, and at a second agent
    /// the rounds its tours ask and tell.
    fn tours(&self) -> Tours {
        let operator = Operator::new(&self.target, &self.token);
        let Ok(Response::Created(other)) = operator.create_agent(Vec::new()) else {
            panic!("another agent")
        };
        let rounds = Rounds::load();
        for (agent, instance) in [(other, ASKED), (other, TOLD), (self.agent, ROUNDS)] {
            let installed = operator.install(agent, &rounds.install(instance)).unwrap();
            assert!(
                matches!(
                    installed,
                    Response::Ran {
                        outcome: Outcome::Done(_),
                        ..
                    }
                ),
                "{installed:?}"
            );
        }
        Tours {
            other,
            methods: rounds.methods,
        }
    }

    /// A tour of one round that then sleeps ten minutes of batch time,
    /// started as `client`, once it sleeps: its id.
    fn napping(&self, client: &mut Client, tours: &Tours) -> WorkflowId {
        let tour = Tour {
            other: tours.other,
            amounts: vec![7],
            nap: 600_000,
            words: 64,
            passes: 4,
        };
        let workflow = self.start_tour(client, tours, &tour);
        wait_until("the tour sleeps", || {
            matches!(
                client.workflow(self.agent, workflow, Duration::ZERO),
                Ok(Response::Workflow {
                    status: WorkflowStatus::Sleeping { .. },
                    ..
                })
            )
        });
        workflow
    }

    /// Start `tour` as `client`: the workflow's id.
    fn start_tour(&self, client: &mut Client, tours: &Tours, tour: &Tour) -> WorkflowId {
        let answer = client
            .call(self.agent, ROUNDS, tours.methods.tour, &tour.arguments())
            .unwrap();
        match answer {
            Response::Ran {
                outcome: Outcome::Started(workflow),
                ..
            } => workflow,
            other => panic!("{other:?}"),
        }
    }
}

/// The status an answer to a workflow's read carries.
#[track_caller]
fn status(answer: Response) -> WorkflowStatus {
    match answer {
        Response::Workflow { status, .. } => status,
        other => panic!("{other:?}"),
    }
}

/// A client's request starts a workflow, answered `Started` with its id;
/// its owner reads its result by the id, waiting for it to end, and every
/// effect of its rounds applied once. Any other key, and an id no
/// workflow has, read nothing, at once.
#[test]
fn a_started_workflows_owner_reads_its_result_by_its_id() {
    let served = Served::start(Arc::new(vos_node::NoHooks));
    let tours = served.tours();
    let mut client = served.client(1);
    let tour = Tour {
        other: tours.other,
        amounts: vec![3, 4, 5],
        nap: 0,
        words: 64,
        passes: 4,
    };
    let workflow = served.start_tour(&mut client, &tours, &tour);
    assert_eq!(
        status(
            client
                .workflow(served.agent, workflow, Duration::from_secs(20))
                .unwrap()
        ),
        WorkflowStatus::Ended(Outcome::Done(tour.result(0)))
    );
    let read = |agent: AgentId, instance: InstanceId, method: MethodId| {
        done(
            client
                .query(
                    agent,
                    instance,
                    method,
                    &[],
                    vos_node::wall_clock() + 10_000,
                )
                .unwrap(),
        )
    };
    let total = tours.methods.total;
    assert_eq!(read(tours.other, ASKED, total), 12);
    assert_eq!(read(served.agent, ROUNDS, total), 12);
    wait_until("the messages apply", || {
        read(tours.other, TOLD, total) == 12
    });

    // Another key: nothing, however long it would wait.
    let stranger = served.client(2);
    let asked = std::time::Instant::now();
    let unknown = stranger
        .workflow(served.agent, workflow, Duration::from_secs(20))
        .unwrap();
    assert_eq!(status(unknown), WorkflowStatus::Unknown);
    assert!(asked.elapsed() < Duration::from_secs(5), "answered at once");
    assert_eq!(
        status(
            client
                .workflow(served.agent, WorkflowId(workflow.0 + 1), Duration::ZERO)
                .unwrap()
        ),
        WorkflowStatus::Unknown
    );
    // Read at a later floor, linearizably, the result stays.
    assert_eq!(
        status(
            client
                .workflow_with(
                    served.agent,
                    workflow,
                    Duration::ZERO,
                    Consistency::Linearizable
                )
                .unwrap()
        ),
        WorkflowStatus::Ended(Outcome::Done(tour.result(0)))
    );
}

/// A read waits no longer than it asks, answering where the workflow
/// stands; one waiting while it sleeps answers once it ends, well within
/// its bound. Reads are signed by the key that reads, and good until their
/// time.
#[test]
fn a_read_waits_for_its_workflow_within_its_bound() {
    let served = Served::start(Arc::new(vos_node::NoHooks));
    let tours = served.tours();
    let mut client = served.client(1);
    let tour = Tour {
        other: tours.other,
        amounts: vec![7],
        nap: 600_000,
        words: 64,
        passes: 4,
    };
    let workflow = served.start_tour(&mut client, &tours, &tour);
    let asked = std::time::Instant::now();
    let sleeping = loop {
        match status(
            client
                .workflow(served.agent, workflow, Duration::from_millis(300))
                .unwrap(),
        ) {
            // Awaiting the other agent's answer, which has yet to apply.
            WorkflowStatus::Awaiting { agent, .. } => assert_eq!(agent, tours.other),
            sleeping => break sleeping,
        }
    };
    assert!(
        matches!(sleeping, WorkflowStatus::Sleeping { until } if until >= served.now() + 590_000),
        "{sleeping:?}"
    );
    assert!(asked.elapsed() >= Duration::from_millis(300), "it waited");

    let waiting = {
        let target = served.target.clone();
        let agent = served.agent;
        let mut kept = client.sessions();
        kept.clear();
        let identities = client.identities();
        std::thread::spawn(move || {
            let client =
                Client::resume(&target, SigningKey::from_bytes(&[1; 32]), kept, identities);
            let started = std::time::Instant::now();
            let answer = client.workflow(agent, workflow, Duration::from_secs(25));
            (answer, started.elapsed())
        })
    };
    std::thread::sleep(Duration::from_millis(200));
    // The sleep comes due, and the next batch, here a call's, steps it.
    served.clock.fetch_add(600_000, Ordering::SeqCst);
    let mut other = served.client(3);
    done(served.call(&mut other, 1));
    let (answer, waited) = waiting.join().unwrap();
    assert_eq!(
        status(answer.unwrap()),
        WorkflowStatus::Ended(Outcome::Done(tour.result(0)))
    );
    assert!(
        waited < Duration::from_secs(15),
        "answered at its end: {waited:?}"
    );

    // Signed by the key that reads, good until its time.
    let identity = client.identity(served.agent).unwrap();
    let key = SigningKey::from_bytes(&[1; 32]);
    let path = format!("/agents/{}/workflows", served.agent.0);
    let now = served.now();
    let consistency = Consistency::Applied { at: 0 };
    let body = signed_read(&identity, &key, now + 10_000, consistency, workflow, 0);
    let (mut read, _) = WorkflowRead::decode(&body).unwrap();
    read.workflow = WorkflowId(workflow.0 + 1);
    assert_eq!(
        served.post(&path, &read.encode()),
        Response::Rejected(Rejection::BadSignature)
    );
    let stale = signed_read(&identity, &key, now - 1, consistency, workflow, 0);
    assert_eq!(
        served.post(&path, &stale),
        Response::Rejected(Rejection::StaleQuery { now })
    );
    // Good no longer than the horizon past its wait: a read captured
    // replays only that long.
    let far = now + workflow_read_horizon(1_000) + 1;
    let ahead = signed_read(&identity, &key, far, consistency, workflow, 1_000);
    assert_eq!(
        served.post(&path, &ahead),
        Response::Rejected(Rejection::StaleQuery { now })
    );
    let within = signed_read(&identity, &key, far - 1, consistency, workflow, 1_000);
    assert!(matches!(
        served.post(&path, &within),
        Response::Workflow { .. }
    ));
    assert!(matches!(
        served.post(&path, &body),
        Response::Workflow {
            status: WorkflowStatus::Ended(_),
            ..
        }
    ));
}

/// A read waits no longer than its node allows, however long it asks; and
/// only so many wait at once: one past them answers at once, and once one
/// ends, the next waits again.
#[test]
fn reads_wait_within_the_nodes_bounds() {
    assert_eq!(
        Config::new(Vec::new()).workflow_wait,
        Duration::from_millis(MAX_WORKFLOW_WAIT_MS)
    );
    let served = Arc::new(Served::start_with(Arc::new(vos_node::NoHooks), |config| {
        config.workflow_wait = Duration::from_secs(3);
        config.workflow_waits = 2;
    }));
    let tours = served.tours();
    let mut client = served.client(1);
    let workflow = served.napping(&mut client, &tours);
    let client = Arc::new(client);
    let read = |wait: Duration| {
        let (served, client) = (Arc::clone(&served), Arc::clone(&client));
        std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let answer = client.workflow(served.agent, workflow, wait).unwrap();
            assert!(matches!(status(answer), WorkflowStatus::Sleeping { .. }));
            started.elapsed()
        })
    };
    let waiting = [read(Duration::from_secs(20)), read(Duration::from_secs(20))];
    std::thread::sleep(Duration::from_millis(500));
    let past = read(Duration::from_secs(20)).join().unwrap();
    assert!(
        past < Duration::from_millis(1_500),
        "answered at once: {past:?}"
    );
    for waited in waiting.map(|reader| reader.join().unwrap()) {
        assert!(
            (Duration::from_millis(2_900)..Duration::from_secs(10)).contains(&waited),
            "waited as long as the node allows: {waited:?}"
        );
    }
    let again = read(Duration::from_secs(1)).join().unwrap();
    assert!(
        again >= Duration::from_millis(950),
        "waits again: {again:?}"
    );
}

/// A read waiting when its node stops ends with it, never waiting out its
/// bound.
#[test]
fn a_read_waiting_ends_when_its_node_stops() {
    let served = Served::start(Arc::new(vos_node::NoHooks));
    let tours = served.tours();
    let mut client = served.client(1);
    let workflow = served.napping(&mut client, &tours);
    let agent = served.agent;
    let reading = std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let answer = client.workflow(agent, workflow, Duration::from_secs(25));
        (answer, started.elapsed())
    });
    std::thread::sleep(Duration::from_millis(300));
    let Served { node, _dir, .. } = served;
    node.shutdown();
    let (answer, waited) = reading.join().unwrap();
    assert!(waited < Duration::from_secs(10), "{waited:?}: {answer:?}");
    assert!(
        !matches!(
            answer,
            Ok(Response::Workflow {
                status: WorkflowStatus::Ended(_),
                ..
            })
        ),
        "{answer:?}"
    );
}

/// An ended workflow's result is kept for its owner about an hour, then
/// collected: its owner reads it unknown, as a stranger does.
#[test]
fn a_collected_workflow_reads_unknown() {
    let served = Served::start(Arc::new(vos_node::NoHooks));
    let tours = served.tours();
    let mut client = served.client(1);
    let tour = Tour {
        other: tours.other,
        amounts: vec![2],
        nap: 0,
        words: 64,
        passes: 4,
    };
    let workflow = served.start_tour(&mut client, &tours, &tour);
    let ended = client
        .workflow(served.agent, workflow, Duration::from_secs(20))
        .unwrap();
    assert_eq!(
        status(ended),
        WorkflowStatus::Ended(Outcome::Done(tour.result(0)))
    );
    // Its collection comes due, and the next batch, here a call's, sweeps.
    served
        .clock
        .fetch_add(defaults::WORKFLOW_KEPT_MS + 1, Ordering::SeqCst);
    let mut other = served.client(3);
    done(served.call(&mut other, 1));
    wait_until("the workflow is collected", || {
        let read = client.workflow(served.agent, workflow, Duration::ZERO);
        matches!(
            read,
            Ok(Response::Workflow {
                status: WorkflowStatus::Unknown,
                ..
            })
        )
    });
}
