//! The gateway in front of real nodes: every route answering its pinned
//! status and body, a client's TLS to it, the operator's envelope in the
//! header, a signed call a
//! compromised gateway alters refused by the node, leader-aware routing
//! and a client's pin across it, the limits per address, refusals for size
//! and from the head that never reach a node, the budget of install-size
//! bodies, a dead node delaying no other's requests, and the transport
//! mark an onion-only agent reads.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use vos_api::{Kind, Mark};
use vos_checker::calls::{install_of, installed};
use vos_checker::programs::Programs;
use vos_checker::spaces::wait_in_process as wait_until;
use vos_gateway::Gateway;
use vos_gateway::front::{self, Http};
use vos_gateway::limits::{Limits, PerAddress};
use vos_gateway::upstream::{Address, Upstream};
use vos_http::routes::operated_header;
use vos_node::client::{Client, Operator, Target, signed_call, signed_operated, signed_query};
use vos_node::{Config, Node, Peers};
use vos_wire::ids::{AgentId, InstanceId, MethodId, Session, WorkflowId};
use vos_wire::ingress::{
    Consistency, Contact, NodeId, OperatorRefusal, Rejection, Response, WorkflowRead,
};
use vos_wire::result::Outcome;
use vos_wire::{Decode, Encode};

const COUNTER: InstanceId = InstanceId(1);
/// The seed of the operator key the nodes list.
const OPERATOR: [u8; 32] = [31; 32];
/// The gateway's seed.
const GATEWAY: [u8; 32] = [41; 32];

mod admission;
mod dead_node;
mod limits;
mod redirects;
mod routes;
mod tls;

fn fresh_nonce() -> [u8; 16] {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    let mut nonce = [0u8; 16];
    nonce[..8].copy_from_slice(&NEXT.fetch_add(1, Ordering::SeqCst).to_le_bytes());
    nonce
}

fn config(programs: &Programs, clock: &Arc<AtomicU64>) -> Config {
    let mut config = Config::new(programs.agent.clone());
    config.executors = 2;
    let clock = Arc::clone(clock);
    config.clock = Arc::new(move || clock.load(Ordering::SeqCst));
    config.operators = vec![SigningKey::from_bytes(&OPERATOR).verifying_key().to_bytes()];
    config
}

/// A gateway serving HTTP on tokio in front of `upstreams`.
struct Front {
    runtime: tokio::runtime::Runtime,
    gateway: Arc<Gateway>,
    address: SocketAddr,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Front {
    fn start(upstreams: Vec<([u8; 32], Address)>, per: PerAddress) -> Self {
        Self::start_with(upstreams, per, None)
    }

    fn start_with(
        upstreams: Vec<([u8; 32], Address)>,
        per: PerAddress,
        tls: Option<Arc<rustls::ServerConfig>>,
    ) -> Self {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        Self::start_on(listener, upstreams, per, tls)
    }

    /// A gateway on `listener`, bound before the space naming it is made.
    fn start_on(
        listener: std::net::TcpListener,
        upstreams: Vec<([u8; 32], Address)>,
        per: PerAddress,
        tls: Option<Arc<rustls::ServerConfig>>,
    ) -> Self {
        Self::start_marked(listener, upstreams, per, tls, Mark::Clearnet)
    }

    /// A gateway on `listener` marking what it relays `mark`: the onion
    /// service's port, where `mark` is [`Mark::Onion`].
    fn start_marked(
        listener: std::net::TcpListener,
        upstreams: Vec<([u8; 32], Address)>,
        per: PerAddress,
        tls: Option<Arc<rustls::ServerConfig>>,
        mark: Mark,
    ) -> Self {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .unwrap();
        let upstreams = upstreams
            .into_iter()
            .map(|(key, address)| Upstream::new(key, address, GATEWAY))
            .collect();
        let gateway = Arc::new(Gateway::new(upstreams));
        listener.set_nonblocking(true).unwrap();
        let listener = {
            let _entered = runtime.enter();
            tokio::net::TcpListener::from_std(listener).unwrap()
        };
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        runtime.spawn(front::serve(
            Arc::clone(&gateway),
            Limits::new(per),
            listener,
            Http {
                tls,
                connections: 64,
                mark,
            },
            async {
                let _ = stopped.await;
            },
        ));
        Self {
            runtime,
            gateway,
            address,
            stop: Some(stop),
        }
    }
}

impl Drop for Front {
    fn drop(&mut self) {
        let _ = self.stop.take().map(|stop| stop.send(()));
    }
}

/// One node with the counter installed, its socket, and a gateway on the
/// socket.
struct Served {
    node: Node,
    socket: PathBuf,
    clock: Arc<AtomicU64>,
    agent: AgentId,
    increment: MethodId,
    value: MethodId,
    front: Front,
    _dir: tempfile::TempDir,
}

impl Served {
    fn start(per: PerAddress) -> Self {
        let programs = Programs::load();
        let dir = tempfile::tempdir().unwrap();
        let clock = Arc::new(AtomicU64::new(vos_node::wall_clock()));
        let node = Node::open(dir.path(), config(&programs, &clock)).unwrap();
        let socket = dir.path().join("api.sock");
        node.serve_socket(&socket, 0o600).unwrap();
        let target = Target::socket(socket.clone());
        let operator = Operator::signing(&target, SigningKey::from_bytes(&OPERATOR), node.id());
        let Ok(Response::Created(agent)) = operator.create_agent(Vec::new()) else {
            panic!("an agent")
        };
        installed(
            operator
                .install(agent, &install_of(COUNTER, &programs.counter_elf))
                .unwrap(),
        );
        let schema = vos_node::client::schema(&target, agent, COUNTER)
            .unwrap()
            .unwrap();
        let front = Front::start(vec![(node.id().0, Address::Socket(socket.clone()))], per);
        Self {
            socket,
            clock,
            agent,
            increment: schema.method_id("increment").unwrap(),
            value: schema.method_id("value").unwrap(),
            front,
            node,
            _dir: dir,
        }
    }

    fn now(&self) -> u64 {
        self.clock.load(Ordering::SeqCst)
    }

    /// An operator's header for a request of `kind` holding `inner`, signed
    /// for this node.
    fn header(&self, kind: Kind, inner: Vec<u8>) -> String {
        let operated = signed_operated(
            self.node.id(),
            &SigningKey::from_bytes(&OPERATOR),
            kind,
            fresh_nonce(),
            self.now() + 60_000,
            inner,
        );
        operated_header(&operated)
    }
}

/// A raw HTTP exchange on a connection of its own: the status, the body,
/// and the whole answer.
fn exchange(address: SocketAddr, request: &[u8]) -> (u16, Vec<u8>, Vec<u8>) {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(30)))
        .unwrap();
    stream.write_all(request).unwrap();
    let mut answer = Vec::new();
    let _ = stream.read_to_end(&mut answer);
    let text = String::from_utf8_lossy(&answer).to_string();
    // The last head's status: a `100 Continue` comes first.
    let head_end = text.rfind("\r\n\r\n").map_or(text.len(), |at| at + 4);
    let last_head = text[..head_end]
        .rsplit("HTTP/1.1 ")
        .next()
        .unwrap_or_default()
        .to_string();
    let status = last_head
        .split_whitespace()
        .next()
        .and_then(|code| code.parse().ok())
        .unwrap_or(0);
    let body_at = answer
        .windows(4)
        .rposition(|window| window == b"\r\n\r\n")
        .map_or(answer.len(), |at| at + 4);
    (status, answer[body_at..].to_vec(), answer)
}

fn request(method: &str, path: &str, headers: &[String], body: &[u8]) -> Vec<u8> {
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: node\r\nConnection: close\r\n");
    for header in headers {
        head += &format!("{header}\r\n");
    }
    head += &format!("Content-Length: {}\r\n\r\n", body.len());
    [head.into_bytes(), body.to_vec()].concat()
}

/// An answer with what differs from run to run zeroed: an applied index,
/// a created id, the stats and a replica's status.
fn masked(status: u16, body: &[u8]) -> (u16, Vec<u8>) {
    let Some(answer) = Response::decode_exact(body) else {
        return (status, body.to_vec());
    };
    let answer = match answer {
        Response::Ran { outcome, .. } => Response::Ran { outcome, at: 0 },
        Response::Created(_) => Response::Created(AgentId(0)),
        Response::Stats(_) | Response::Status(_) => Response::Busy,
        Response::Workflow { status, .. } => Response::Workflow { status, at: 0 },
        Response::Rejected(Rejection::StaleQuery { .. }) => {
            Response::Rejected(Rejection::StaleQuery { now: 0 })
        }
        other => other,
    };
    (status, answer.encode())
}
