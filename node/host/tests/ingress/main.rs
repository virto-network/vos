//! The node's HTTP ingress and its API's socket, end to end on the default
//! agent and the counter actor: client-named sessions, signed calls in
//! their sequences, the reply window, expiry, the operator's token,
//! workflows started by clients and read by their owners, and the API's
//! frames.

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

mod api;
mod operator;
mod operator_api;
mod quic;
mod requests;
mod sessions;
mod workflows;

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use std::collections::HashMap;

use vos_checker::calls::{done, install_of, installed};
use vos_checker::hooks::{FailNextSync, Gate, carries};
use vos_checker::programs::Programs;
use vos_checker::rounds::{ASKED, ROUNDS, Rounds, TOLD, Tour, TourMethods, signed_read};
use vos_checker::spaces::wait_in_process as wait_until;
use vos_node::client::{self, Client, ClientError, Operator, Target};
use vos_node::{ADMIN_TOKEN, Config, Hooks, Node};
use vos_wire::abi::Refusal;
use vos_wire::batch::Batch;
use vos_wire::ids::{AgentId, InstanceId, MethodId, Session, WorkflowId};
use vos_wire::ingress::{
    Call, Consistency, MAX_WORKFLOW_WAIT_MS, Rejection, Response, WorkflowRead, WorkflowStatus,
    workflow_read_horizon,
};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};
use vos_wire::{defaults, expiry, keys};

const COUNTER: InstanceId = InstanceId(1);
/// The seed of the operator key every served node lists.
const OPERATOR: [u8; 32] = [31; 32];

/// A node serving ingress, with one agent running the counter.
struct Served {
    node: Node,
    address: SocketAddr,
    target: Target,
    /// The node API's unix socket.
    socket: std::path::PathBuf,
    clock: Arc<AtomicU64>,
    token: String,
    agent: AgentId,
    increment: MethodId,
    value: MethodId,
    _dir: tempfile::TempDir,
}

impl Served {
    /// A node with no hooks.
    fn plain() -> Self {
        Self::start(Arc::new(vos_node::NoHooks))
    }

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
        config.operators = vec![SigningKey::from_bytes(&OPERATOR).verifying_key().to_bytes()];
        configure(&mut config);
        let node = Node::open(dir.path(), config).unwrap();
        let address = node.serve("127.0.0.1:0".parse().unwrap()).unwrap();
        let socket = dir.path().join("api.sock");
        node.serve_socket(&socket, 0o600).unwrap();
        let target = Target::loopback(&format!("http://{address}")).unwrap();
        let token = std::fs::read_to_string(dir.path().join(ADMIN_TOKEN)).unwrap();
        let operator = Operator::new(&target, &token);
        let Ok(Response::Created(agent)) = operator.create_agent(Vec::new()) else {
            panic!("an agent")
        };
        let install = install_of(COUNTER, &programs.counter_elf);
        installed(operator.install(agent, &install).unwrap());
        let schema = vos_node::client::schema(&target, agent, COUNTER)
            .unwrap()
            .expect("an installed schema");
        Self {
            node,
            address,
            target,
            socket,
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

    /// An operator request of `kind` holding `body`, signed by the listed
    /// operator key for this node, with a fresh nonce, good for a minute.
    fn operated(&self, kind: vos_api::Kind, body: Vec<u8>) -> Vec<u8> {
        client::signed_operated(
            self.node.id(),
            &SigningKey::from_bytes(&OPERATOR),
            kind,
            fresh_nonce(),
            self.now() + 60_000,
            body,
        )
        .encode()
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

/// A nonce no other request of this process holds.
fn fresh_nonce() -> [u8; 16] {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let mut nonce = [0u8; 16];
    nonce[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::SeqCst).to_le_bytes());
    nonce
}

/// The status line a raw request gets.
fn status_line(address: SocketAddr, request: &[u8]) -> String {
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
