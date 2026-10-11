//! The node's HTTP ingress, end to end on the default agent and the
//! counter actor: client-named sessions, signed calls in their sequences,
//! the reply window, expiry, and the operator's token.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use std::collections::HashMap;

use vos_node::client::{self, Client, ClientError, Operator, Target};
use vos_node::store::{Store, View};
use vos_node::{ADMIN_TOKEN, Config, Hooks, Node};
use vos_wire::abi::refusal;
use vos_wire::batch::{Batch, Input};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Session};
use vos_wire::ingress::{Answer, Call, Install, Rejection};
use vos_wire::result::Outcome;
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode};
use vos_wire::{defaults, expiry, keys};

const COUNTER: InstanceId = InstanceId(1);

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
}

fn method(schema: &Schema, name: &str) -> MethodId {
    schema
        .methods
        .iter()
        .find(|method| method.name == name.as_bytes())
        .unwrap_or_else(|| panic!("no method {name}"))
        .id
}

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
        let node = Node::open(dir.path(), config).unwrap();
        let address = node.serve("127.0.0.1:0".parse().unwrap()).unwrap();
        let base = format!("http://{address}");
        let target = Target::loopback(&base).unwrap();
        let token = std::fs::read_to_string(dir.path().join(ADMIN_TOKEN)).unwrap();
        let operator = Operator::new(&target, &token);
        let Ok(Answer::Created(agent)) = operator.create_agent(Vec::new()) else {
            panic!("an agent")
        };
        let install = Install {
            instance: COUNTER,
            program: programs.counter.clone(),
            attestables: Vec::new(),
            roles: Vec::new(),
        };
        let installed = operator.install(agent, &install).unwrap();
        assert!(
            matches!(
                installed,
                Answer::Ran {
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
            increment: method(&schema, "increment"),
            value: method(&schema, "value"),
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
    fn call(&self, client: &mut Client, by: u64) -> Answer {
        client
            .call(self.agent, COUNTER, self.increment, &by.encode())
            .unwrap()
    }

    fn increment(&self, client: &Client, sequence: u64, by: u64) -> Answer {
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

    fn post(&self, path: &str, body: &[u8]) -> Answer {
        let (_, body) = vos_node::client::post(&self.target, path, body).unwrap();
        Answer::decode(&body).unwrap().0
    }
}

fn done(answer: Answer) -> u64 {
    match answer {
        Answer::Ran {
            outcome: Outcome::Done(bytes),
            ..
        } => u64::decode(&bytes).unwrap().0,
        other => panic!("not done: {other:?}"),
    }
}

fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let until = Instant::now() + Duration::from_secs(20);
    while !done() {
        assert!(Instant::now() < until, "timed out: {what}");
        std::thread::sleep(Duration::from_millis(5));
    }
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
        Answer::Rejected(Rejection::Gap { expected: 2 })
    );
    assert_eq!(
        served.increment(&client, 0, 1),
        Answer::Rejected(Rejection::Gap { expected: 2 })
    );
    assert_eq!(
        served.increment(&client, 2 + defaults::REPLY_WINDOW, 1),
        Answer::Rejected(Rejection::Ahead)
    );
    for sequence in 2..=defaults::REPLY_WINDOW + 1 {
        done(served.increment(&client, sequence, 1));
    }
    assert_eq!(
        served.increment(&client, 1, 5),
        Answer::Rejected(Rejection::TooOld)
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
        Answer::Rejected(Rejection::BadSignature),
        "arguments changed after signing"
    );
    // The session is in the signed bytes, and its key signs.
    call = Call::decode(&body).unwrap().0;
    call.session.name[0] ^= 1;
    assert_eq!(
        served.post(&path, &call.encode()),
        Answer::Rejected(Rejection::BadSignature)
    );
    call = Call::decode(&body).unwrap().0;
    call.session.key = SigningKey::from_bytes(&[2; 32]).verifying_key().to_bytes();
    assert_eq!(
        served.post(&path, &call.encode()),
        Answer::Rejected(Rejection::BadSignature)
    );
    // Signed for one agent, sent to another: the agent's identity is in
    // the signed bytes.
    let operator = Operator::new(&served.target, &served.token);
    let Ok(Answer::Created(other)) = operator.create_agent(Vec::new()) else {
        panic!("another agent")
    };
    let elsewhere = format!("/agents/{}/calls", other.0);
    assert_eq!(
        served.post(&elsewhere, &body),
        Answer::Rejected(Rejection::BadSignature)
    );
    assert_eq!(
        served.post(&format!("/agents/{}/calls", other.0 + 1), &body),
        Answer::NoAgent
    );
    body.truncate(body.len() - 1);
    assert_eq!(
        served.post(&path, &body),
        Answer::Rejected(Rejection::Malformed)
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
        assert_eq!(stale(t0), Answer::Rejected(Rejection::StaleSession { now }));
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
        Answer::Rejected(Rejection::StaleQuery { now })
    );
    assert_eq!(
        query(vos_node::wall_clock() + 600_000),
        Answer::Rejected(Rejection::StaleQuery { now })
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
        Answer::Refused(refusal::EXPIRED)
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
        Answer::TimedOut,
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

/// Holds every commit while `held`, counting the commits that reached it.
#[derive(Default)]
struct Gate {
    held: Mutex<bool>,
    released: Condvar,
    reached: AtomicU64,
}

impl Hooks for Gate {
    fn before_commit(&self) {
        self.reached.fetch_add(1, Ordering::SeqCst);
        let mut held = self.held.lock().unwrap();
        while *held {
            held = self.released.wait(held).unwrap();
        }
    }
}

#[test]
fn a_duplicate_in_flight_waits_for_its_answer() {
    let gate = Arc::new(Gate::default());
    let served = Arc::new(Served::start(gate.clone()));
    let client = Arc::new(served.client(1));
    *gate.held.lock().unwrap() = true;
    let reached = gate.reached.load(Ordering::SeqCst);
    let first = {
        let (served, client) = (Arc::clone(&served), Arc::clone(&client));
        std::thread::spawn(move || served.increment(&client, 1, 5))
    };
    wait_until("the first is in flight", || {
        gate.reached.load(Ordering::SeqCst) > reached
    });
    let second = {
        let (served, client) = (Arc::clone(&served), Arc::clone(&client));
        std::thread::spawn(move || served.increment(&client, 1, 5))
    };
    std::thread::sleep(Duration::from_millis(100));
    *gate.held.lock().unwrap() = false;
    gate.released.notify_all();
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
        Answer::Rejected(Rejection::Unauthorized)
    );
    let client = served.client(1);
    assert_eq!(
        stranger
            .grant(served.agent, client.principal(), Some(1))
            .unwrap(),
        Answer::Rejected(Rejection::Unauthorized)
    );
    assert_eq!(
        served.node.id(),
        vos_node::client::node_id(&served.target).unwrap()
    );
}

/// Fails the sync of the next synced flush once armed, as a failed fsync
/// does.
#[derive(Default)]
struct FailNextSync(AtomicBool);

impl Hooks for FailNextSync {
    fn fail_sync(&self) -> bool {
        self.0.swap(false, Ordering::SeqCst)
    }
}

/// The operator reads a replica's status, and a stranger cannot. A node
/// of a space of one whose flush fails outside any log write halts, and
/// its status says so.
#[test]
fn the_status_route_reports_a_replica_and_a_halt() {
    let hooks = Arc::new(FailNextSync::default());
    let served = Served::start(hooks.clone());
    let operator = Operator::new(&served.target, &served.token);
    let Ok(Answer::Status(status)) = operator.status(served.agent) else {
        panic!("a status")
    };
    assert!(status.leads && !status.halted, "{status:?}");
    assert!(status.applied >= 1 && status.commit >= status.applied);
    assert!(status.last_index >= status.commit);
    let stranger = Operator::new(&served.target, &"00".repeat(32));
    assert_eq!(
        stranger.status(served.agent).unwrap(),
        Answer::Rejected(Rejection::Unauthorized)
    );
    assert_eq!(operator.status(AgentId(0xdead)).unwrap(), Answer::NoAgent);
    hooks.0.store(true, Ordering::SeqCst);
    assert!(
        served.node.create_agent().is_err(),
        "the record's flush failed"
    );
    wait_until("the node halts", || {
        matches!(
            operator.status(served.agent),
            Ok(Answer::Status(status)) if status.halted
        )
    });
}

#[test]
fn a_node_is_its_public_key_and_never_serves_its_secret() {
    use std::os::unix::fs::PermissionsExt;
    use vos_node::store::{Fjall, Store};
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

/// Holds the refine of a batch holding the poisoned arguments until
/// released, then fails it, once; and holds commits while asked.
#[derive(Default)]
struct GatedPoison {
    poison: Vec<u8>,
    held: Mutex<bool>,
    released: Condvar,
    armed: AtomicBool,
    reached: AtomicU64,
    commits_held: Mutex<bool>,
    commits_released: Condvar,
    commits_reached: AtomicU64,
}

impl Hooks for GatedPoison {
    fn fail_refine(&self, _: AgentId, batch: &Batch) -> bool {
        let poisoned = batch.inputs.iter().any(
            |input| matches!(input, Input::Request(request) if request.arguments == self.poison),
        );
        if !poisoned || !self.armed.load(Ordering::SeqCst) {
            return false;
        }
        self.reached.fetch_add(1, Ordering::SeqCst);
        let mut held = self.held.lock().unwrap();
        while *held {
            held = self.released.wait(held).unwrap();
        }
        self.armed.swap(false, Ordering::SeqCst)
    }

    fn before_commit(&self) {
        self.commits_reached.fetch_add(1, Ordering::SeqCst);
        let mut held = self.commits_held.lock().unwrap();
        while *held {
            held = self.commits_released.wait(held).unwrap();
        }
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
    *gate.held.lock().unwrap() = true;
    gate.armed.store(true, Ordering::SeqCst);
    let send = |sequence: u64| {
        let (served, client) = (Arc::clone(&served), Arc::clone(&client));
        std::thread::spawn(move || served.increment(&client, sequence, sequence))
    };
    let first = send(1);
    wait_until("the first is refined", || {
        gate.reached.load(Ordering::SeqCst) > 0
    });
    let second = send(2);
    std::thread::sleep(Duration::from_millis(100));
    let third = send(3);
    std::thread::sleep(Duration::from_millis(100));
    // The batch of 2 and 3 will wait at its commit, so they stay in flight.
    *gate.commits_held.lock().unwrap() = true;
    let commits = gate.commits_reached.load(Ordering::SeqCst);
    *gate.held.lock().unwrap() = false;
    gate.released.notify_all();
    assert_eq!(first.join().unwrap(), Answer::NotConsumed);
    wait_until("2 and 3 reach their commit", || {
        gate.commits_reached.load(Ordering::SeqCst) > commits
    });
    // Resent while 2 and 3 are in flight: the lane went back to before 1.
    let resent = send(1);
    std::thread::sleep(Duration::from_millis(100));
    *gate.commits_held.lock().unwrap() = false;
    gate.commits_released.notify_all();
    assert_eq!(second.join().unwrap(), Answer::Refused(refusal::SEQUENCE));
    assert_eq!(third.join().unwrap(), Answer::Refused(refusal::SEQUENCE));
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
