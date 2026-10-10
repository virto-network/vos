//! The node's HTTP ingress, end to end on the default agent and the
//! counter actor: sessions, signed calls in their sequences, the reply
//! window, expiry, and the operator's token.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use vos_node::client::{Client, Operator, Target};
use vos_node::{ADMIN_TOKEN, Config, Hooks, Node};
use vos_wire::abi::refusal;
use vos_wire::batch::{Batch, Input};
use vos_wire::defaults;
use vos_wire::ids::{AgentId, InstanceId, MethodId};
use vos_wire::ingress::{Answer, Call, Install, Open, Rejection, open_message};
use vos_wire::result::Outcome;
use vos_wire::schema::Schema;
use vos_wire::{Decode, Encode};

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
            matches!(installed, Answer::Ran(Outcome::Done(_))),
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
        Client::open(
            &self.target,
            SigningKey::from_bytes(&[seed; 32]),
            self.now(),
        )
        .unwrap()
    }

    fn increment(&self, client: &Client, sequence: u64, by: u64) -> Answer {
        client
            .call_at(self.agent, sequence, COUNTER, self.increment, &by.encode())
            .unwrap()
    }

    fn value(&self, client: &Client) -> u64 {
        let answer = client
            .query(self.agent, COUNTER, self.value, &[], self.now() + 10_000)
            .unwrap();
        done(answer)
    }

    fn post(&self, path: &str, body: &[u8]) -> Answer {
        let (_, body) = vos_node::client::post(&self.target, path, body).unwrap();
        Answer::decode(&body).unwrap().0
    }
}

fn done(answer: Answer) -> u64 {
    match answer {
        Answer::Ran(Outcome::Done(bytes)) => u64::decode(&bytes).unwrap().0,
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

    let mut body = client.call_body(agent, 1, COUNTER, served.increment, &5u64.encode());
    let (mut call, _) = Call::decode(&body).unwrap();
    call.arguments = 6u64.encode();
    assert_eq!(
        served.post(&path, &call.encode()),
        Answer::Rejected(Rejection::BadSignature),
        "arguments changed after signing"
    );
    call = Call::decode(&body).unwrap().0;
    call.session.0 += 1000;
    assert_eq!(
        served.post(&path, &call.encode()),
        Answer::Rejected(Rejection::UnknownSession)
    );
    // Signed for one agent, sent to another: the agent is in the signed
    // bytes.
    let elsewhere = format!("/agents/{}/calls", agent.0 + 1);
    assert_eq!(
        served.post(&elsewhere, &body),
        Answer::Rejected(Rejection::BadSignature)
    );
    body.truncate(body.len() - 1);
    assert_eq!(
        served.post(&path, &body),
        Answer::Rejected(Rejection::Malformed)
    );

    // A captured open cannot be replayed, nor signed far off the clock.
    let key = SigningKey::from_bytes(&[9; 32]);
    let node = vos_node::client::node_id(&served.target).unwrap();
    let public = key.verifying_key().to_bytes();
    let open = |time: u64| {
        use ed25519_dalek::Signer;
        Open {
            key: public,
            time,
            signature: key.sign(&open_message(&node, &public, time)).to_bytes(),
        }
        .encode()
    };
    let first = open(served.now());
    assert_eq!(served.status("/sessions", &first), 200);
    assert_eq!(
        served.post("/sessions", &first),
        Answer::Rejected(Rejection::StaleOpen)
    );
    assert_eq!(
        served.post("/sessions", &open(served.now() + 120_000)),
        Answer::Rejected(Rejection::StaleOpen)
    );

    let now = served.now();
    let query = |not_after| {
        client
            .query(agent, COUNTER, served.value, &[], not_after)
            .unwrap()
    };
    assert_eq!(query(now - 1), Answer::Rejected(Rejection::StaleQuery));
    assert_eq!(
        query(now + 600_000),
        Answer::Rejected(Rejection::StaleQuery)
    );
    assert_eq!(done(query(now + 1_000)), 0);
}

impl Served {
    fn status(&self, path: &str, body: &[u8]) -> u16 {
        vos_node::client::post(&self.target, path, body).unwrap().0
    }
}

#[test]
fn an_expired_session_is_refused() {
    let served = Served::start(Arc::new(vos_node::NoHooks));
    let client = served.client(1);
    assert_eq!(done(served.increment(&client, 1, 5)), 5);
    served
        .clock
        .fetch_add(defaults::SESSION_EXPIRY_MS + 1, Ordering::SeqCst);
    assert_eq!(
        served.increment(&client, 2, 1),
        Answer::Refused(refusal::EXPIRED)
    );
    let renewed = served.client(1);
    assert_eq!(done(served.increment(&renewed, 1, 1)), 6);
}

#[test]
fn pipelined_requests_recover_their_lost_replies() {
    let served = Served::start(Arc::new(vos_node::NoHooks));
    let client = served.client(1);
    let address: SocketAddr = served.base.trim_start_matches("http://").parse().unwrap();
    let mut stream = TcpStream::connect(address).unwrap();
    for (sequence, by) in [(1u64, 1u64), (2, 2), (3, 3)] {
        let body = client.call_body(
            served.agent,
            sequence,
            COUNTER,
            served.increment,
            &by.encode(),
        );
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
