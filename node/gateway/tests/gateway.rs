//! The gateway in front of real nodes: every route answering as the node's
//! own HTTP does, the operator's envelope in the header, a signed call a
//! compromised gateway alters refused by the node, leader-aware routing
//! and a client's pin across it, the limits per address, refusals for size
//! and from the head that never reach a node, the budget of install-size
//! bodies, and a dead node delaying no other's requests.

use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use vos_api::Kind;
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
use vos_wire::ids::{AgentId, InstanceId, MethodId, WorkflowId};
use vos_wire::ingress::{
    Consistency, Contact, NodeId, OperatorRefusal, Rejection, Response, WorkflowRead,
};
use vos_wire::{Decode, Encode};

const COUNTER: InstanceId = InstanceId(1);
/// The seed of the operator key the nodes list.
const OPERATOR: [u8; 32] = [31; 32];
/// The gateway's seed.
const GATEWAY: [u8; 32] = [41; 32];

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

/// One node with the counter installed, its own HTTP and its socket, and
/// a gateway on the socket.
struct Served {
    node: Node,
    http: SocketAddr,
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
        let http = node.serve("127.0.0.1:0".parse().unwrap()).unwrap();
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
            http,
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

/// An answer with what legitimately differs between two runs of one
/// request zeroed: an applied index, a created id, the stats and a
/// replica's status.
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

#[test]
fn every_route_through_the_gateway_answers_as_the_nodes_http() {
    let served = Served::start(PerAddress::default());
    let agent = served.agent.0;
    let key = SigningKey::from_bytes(&[5; 32]);
    let client = Client::new(&Target::socket(served.socket.clone()), key.clone());
    let identity = client.identity(served.agent).unwrap();
    let call = signed_call(
        &identity,
        &key,
        client.session(served.agent),
        1,
        COUNTER,
        served.increment,
        4u64.encode(),
    )
    .encode();
    let query = signed_query(
        &identity,
        &key,
        served.now() + 60_000,
        Consistency::Applied { at: 0 },
        COUNTER,
        served.value,
        Vec::new(),
    )
    .encode();
    let stale_query = signed_query(
        &identity,
        &key,
        served.now() - 1,
        Consistency::Applied { at: 0 },
        COUNTER,
        served.value,
        Vec::new(),
    )
    .encode();
    let mut workflow = WorkflowRead {
        key: key.verifying_key().to_bytes(),
        not_after: served.now() + 60_000,
        consistency: Consistency::Applied { at: 0 },
        workflow: WorkflowId(77),
        wait_ms: 0,
        signature: [0; 64],
    };
    use ed25519_dalek::Signer;
    workflow.signature = key.sign(&workflow.message(&identity)).to_bytes();
    let workflow = workflow.encode();
    let oversize = vec![0u8; vos_wire::abi::cap::REQUEST + vos_api::ENVELOPE + 1];
    let grant = vos_wire::ingress::Grant {
        principal: vos_wire::ids::Principal::Client([9; 32]),
        role: Some(1),
    }
    .encode();
    // A first call of a session of its own for each front, adding 0: both
    // fronts' calls run, and answer the same total.
    let callers = AtomicU64::new(60);
    let first_call = || {
        let seed = callers.fetch_add(1, Ordering::SeqCst) as u8;
        let key = SigningKey::from_bytes(&[seed; 32]);
        let client = Client::new(&Target::socket(served.socket.clone()), key.clone());
        signed_call(
            &identity,
            &key,
            client.session(served.agent),
            1,
            COUNTER,
            served.increment,
            0u64.encode(),
        )
        .encode()
    };
    // A header whose command already ran: replayed at both fronts.
    let ran = served.header(Kind::Reports, [agent.encode(), true.encode()].concat());
    let reports = format!("/agents/{agent}/reports");
    let (status, _, _) = exchange(
        served.http,
        &request(
            "POST",
            &reports,
            &[format!("Authorization: {ran}")],
            &true.encode(),
        ),
    );
    assert_eq!(status, 200);
    let header_for = |node: NodeId, expires_ms: u64| {
        operated_header(&signed_operated(
            node,
            &SigningKey::from_bytes(&OPERATOR),
            Kind::Stats,
            fresh_nonce(),
            expires_ms,
            Vec::new(),
        ))
    };
    let expired = header_for(served.node.id(), served.now() - 1);
    let elsewhere = header_for(NodeId([3; 32]), served.now() + 60_000);
    let create = vos_wire::ingress::Create { replicas: vec![1] }.encode();
    // An install that runs: the counter, on an agent made for each front.
    let counter = install_of(COUNTER, &Programs::load().counter_elf).encode();
    let fresh_agent = || {
        let operator = Operator::signing(
            &Target::socket(served.socket.clone()),
            SigningKey::from_bytes(&OPERATOR),
            served.node.id(),
        );
        match operator.create_agent(Vec::new()) {
            Ok(Response::Created(agent)) => agent.0,
            other => panic!("an agent: {other:?}"),
        }
    };
    let replace = vos_wire::ingress::Replace { remove: 5, add: 6 }.encode();
    // Each request, made fresh for each front: an operator's header is
    // good once.
    type Make<'a> = Box<dyn Fn() -> Vec<u8> + 'a>;
    let corpus: Vec<(&str, Make)> = vec![
        ("node key", Box::new(|| request("GET", "/", &[], b""))),
        ("time", Box::new(|| request("GET", "/time", &[], b""))),
        (
            "an agent",
            Box::new(|| request("GET", &format!("/agents/{agent}"), &[], b"")),
        ),
        (
            "no agent",
            Box::new(|| request("GET", "/agents/99999", &[], b"")),
        ),
        ("no id", Box::new(|| request("GET", "/agents/x", &[], b""))),
        (
            "a schema",
            Box::new(|| {
                request(
                    "GET",
                    &format!("/agents/{agent}/instances/1/schema"),
                    &[],
                    b"",
                )
            }),
        ),
        (
            "no schema",
            Box::new(|| {
                request(
                    "GET",
                    &format!("/agents/{agent}/instances/9/schema"),
                    &[],
                    b"",
                )
            }),
        ),
        (
            "a schema, no id",
            Box::new(|| {
                request(
                    "GET",
                    &format!("/agents/{agent}/instances/x/schema"),
                    &[],
                    b"",
                )
            }),
        ),
        (
            "a call",
            Box::new(|| request("POST", &format!("/agents/{agent}/calls"), &[], &call)),
        ),
        (
            "a malformed call",
            Box::new(|| request("POST", &format!("/agents/{agent}/calls"), &[], b"junk")),
        ),
        (
            "a call, no id",
            Box::new(|| request("POST", "/agents/x/calls", &[], &call)),
        ),
        (
            "a call past its limit",
            Box::new(|| request("POST", &format!("/agents/{agent}/calls"), &[], &oversize)),
        ),
        (
            "a query",
            Box::new(|| request("POST", &format!("/agents/{agent}/queries"), &[], &query)),
        ),
        (
            "a stale query",
            Box::new(|| {
                request(
                    "POST",
                    &format!("/agents/{agent}/queries"),
                    &[],
                    &stale_query,
                )
            }),
        ),
        (
            "a workflow",
            Box::new(|| {
                request(
                    "POST",
                    &format!("/agents/{agent}/workflows"),
                    &[],
                    &workflow,
                )
            }),
        ),
        (
            "an unknown path",
            Box::new(|| request("GET", "/nothing", &[], b"")),
        ),
        (
            "a known path, another method",
            Box::new(|| request("PUT", "/agents", &[], b"")),
        ),
        (
            "Expect",
            Box::new(|| {
                let mut bytes = format!("POST /agents/{agent}/queries HTTP/1.1\r\nHost: node\r\nConnection: close\r\nExpect: 100-continue\r\nContent-Length: {}\r\n\r\n", query.len()).into_bytes();
                bytes.extend_from_slice(&query);
                bytes
            }),
        ),
        (
            "chunked",
            Box::new(|| {
                format!("POST /agents/{agent}/calls HTTP/1.1\r\nHost: node\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n").into_bytes()
            }),
        ),
        (
            "a head too large",
            Box::new(|| {
                format!(
                    "GET / HTTP/1.1\r\nHost: node\r\nX: {}\r\n\r\n",
                    "a".repeat(17 << 10)
                )
                .into_bytes()
            }),
        ),
        (
            "stats",
            Box::new(|| {
                request(
                    "GET",
                    "/stats",
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Stats, Vec::new())
                    )],
                    b"",
                )
            }),
        ),
        (
            "status",
            Box::new(|| {
                request(
                    "GET",
                    &format!("/agents/{agent}/status"),
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Status, agent.encode())
                    )],
                    b"",
                )
            }),
        ),
        (
            "a grant",
            Box::new(|| {
                request(
                    "POST",
                    &format!("/agents/{agent}/roles"),
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Grant, [agent.encode(), grant.clone()].concat())
                    )],
                    &grant,
                )
            }),
        ),
        (
            "an agent created",
            Box::new(|| {
                request(
                    "POST",
                    "/agents",
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::CreateAgent, Vec::new())
                    )],
                    b"",
                )
            }),
        ),
        (
            "an install",
            Box::new(|| {
                let agent = fresh_agent();
                request(
                    "POST",
                    &format!("/agents/{agent}/install"),
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Install, [agent.encode(), counter.clone()].concat())
                    )],
                    &counter,
                )
            }),
        ),
        (
            "an install, malformed",
            Box::new(|| {
                request(
                    "POST",
                    &format!("/agents/{agent}/install"),
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Install, [agent.encode(), b"elf".to_vec()].concat())
                    )],
                    b"elf",
                )
            }),
        ),
        (
            "an operator's route, no id",
            Box::new(|| {
                request(
                    "POST",
                    "/agents/x/reports",
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Reports, Vec::new())
                    )],
                    &true.encode(),
                )
            }),
        ),
        (
            "an operator's route, no header",
            Box::new(|| request("GET", "/stats", &[], b"")),
        ),
        (
            "an operator's route, a bad header",
            Box::new(|| {
                request(
                    "GET",
                    "/stats",
                    &["Authorization: Operated !!".to_string()],
                    b"",
                )
            }),
        ),
        (
            "a first call",
            Box::new(|| {
                request(
                    "POST",
                    &format!("/agents/{agent}/calls"),
                    &[],
                    &first_call(),
                )
            }),
        ),
        (
            "a read with a body",
            Box::new(|| request("GET", &format!("/agents/{agent}"), &[], b"ignored")),
        ),
        (
            "an agent created on replicas",
            Box::new(|| {
                request(
                    "POST",
                    "/agents",
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::CreateAgent, create.clone())
                    )],
                    &create,
                )
            }),
        ),
        (
            "a representative",
            Box::new(|| {
                request(
                    "POST",
                    "/representative",
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::CreateRepresentative, Vec::new())
                    )],
                    b"",
                )
            }),
        ),
        (
            "reports",
            Box::new(|| {
                request(
                    "POST",
                    &reports,
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Reports, [agent.encode(), false.encode()].concat())
                    )],
                    &false.encode(),
                )
            }),
        ),
        (
            "a replacement",
            Box::new(|| {
                request(
                    "POST",
                    &format!("/agents/{agent}/replicas"),
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Replace, [agent.encode(), replace.clone()].concat())
                    )],
                    &replace,
                )
            }),
        ),
        (
            "a replayed command",
            Box::new(|| {
                request(
                    "POST",
                    &reports,
                    &[format!("Authorization: {ran}")],
                    &true.encode(),
                )
            }),
        ),
        (
            "an expired read",
            Box::new(|| request("GET", "/stats", &[format!("Authorization: {expired}")], b"")),
        ),
        (
            "a read signed for another node",
            Box::new(|| {
                request(
                    "GET",
                    "/stats",
                    &[format!("Authorization: {elsewhere}")],
                    b"",
                )
            }),
        ),
        (
            "an operator's route, signed for another agent",
            Box::new(|| {
                request(
                    "GET",
                    &format!("/agents/{agent}/status"),
                    &[format!(
                        "Authorization: {}",
                        served.header(Kind::Status, 1u32.encode())
                    )],
                    b"",
                )
            }),
        ),
    ];
    for (name, make) in &corpus {
        let (node_status, node_body, node_raw) = exchange(served.http, &make());
        let (front_status, front_body, front_raw) = exchange(served.front.address, &make());
        assert_eq!(
            masked(node_status, &node_body),
            masked(front_status, &front_body),
            "{name}"
        );
        assert_ne!(node_status, 0, "{name}");
        let _ = (node_raw, front_raw);
    }
    // `Expect: 100-continue`: each says go on before the body is sent.
    let expect = |address: SocketAddr| {
        let mut stream = TcpStream::connect(address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(30)))
            .unwrap();
        let head = format!(
            "POST /agents/{agent}/queries HTTP/1.1\r\nHost: node\r\nConnection: close\r\nExpect: 100-continue\r\nContent-Length: {}\r\n\r\n",
            query.len()
        );
        stream.write_all(head.as_bytes()).unwrap();
        let mut go_on = [0u8; 25];
        stream.read_exact(&mut go_on).unwrap();
        assert_eq!(&go_on, b"HTTP/1.1 100 Continue\r\n\r\n");
        stream.write_all(&query).unwrap();
        let mut rest = Vec::new();
        let _ = stream.read_to_end(&mut rest);
        String::from_utf8_lossy(&rest)
            .lines()
            .next()
            .unwrap_or_default()
            .to_string()
    };
    assert_eq!(expect(served.http), expect(served.front.address));
}

/// A gateway that alters a byte of a signed call's arguments gets the
/// node's `BadSignature`: it can forge nothing.
#[test]
fn a_gateway_altering_a_signed_call_is_refused() {
    let served = Served::start(PerAddress::default());
    let key = SigningKey::from_bytes(&[6; 32]);
    let client = Client::new(&Target::socket(served.socket.clone()), key.clone());
    let identity = client.identity(served.agent).unwrap();
    let mut call = signed_call(
        &identity,
        &key,
        client.session(served.agent),
        1,
        COUNTER,
        served.increment,
        7u64.encode(),
    );
    call.arguments[0] ^= 1;
    let upstream = Upstream::new(
        served.node.id().0,
        Address::Socket(served.socket.clone()),
        GATEWAY,
    );
    let body = (served.agent, call).encode();
    let (kind, answer) = served
        .front
        .runtime
        .block_on(upstream.request(Kind::Call as u16, &body))
        .unwrap();
    assert_eq!(kind, Kind::Call as u16);
    assert_eq!(
        Response::decode_exact(&answer),
        Some(Response::Rejected(Rejection::BadSignature))
    );
}

/// Past its burst an address is answered 429, before any node is asked.
#[test]
fn an_address_past_its_burst_is_answered_429() {
    let served = Served::start(PerAddress {
        connections: 64,
        rate: 1,
        burst: 3,
    });
    let statuses: Vec<u16> = (0..5)
        .map(|_| exchange(served.front.address, &request("GET", "/time", &[], b"")).0)
        .collect();
    assert_eq!(&statuses[..3], &[200, 200, 200]);
    assert_eq!(statuses[4], 429);
    // Decided from the head: an install-size body is never waited for.
    let header = served.header(Kind::Install, served.agent.encode());
    assert_eq!(install_head(&served, &header).0, 429);
}

/// The head of an install as large as an install may be, its body unsent:
/// the answer, if one comes before the body is asked for.
fn install_head(served: &Served, authorization: &str) -> (u16, Vec<u8>, Vec<u8>) {
    exchange(
        served.front.address,
        install_request(served, authorization).as_bytes(),
    )
}

fn install_request(served: &Served, authorization: &str) -> String {
    format!(
        "POST /agents/{}/install HTTP/1.1\r\nHost: node\r\nAuthorization: {authorization}\r\nContent-Length: {}\r\n\r\n",
        served.agent.0,
        vos_wire::abi::cap::MAX_ELF
    )
}

/// At most four install-size bodies are held at once: a fifth is answered
/// 503 from its head. An operator's route without an envelope, or with one
/// signed for a node behind no upstream, is answered from its head as the
/// whole request would be, and holds none of the four. No node is asked.
#[test]
fn install_size_bodies_are_bounded_and_refused_from_their_heads() {
    let served = Served::start(PerAddress::default());
    let before = served.node.api_frames();
    let held: Vec<TcpStream> = (0..vos_http::LARGE)
        .map(|_| {
            let mut stream = TcpStream::connect(served.front.address).unwrap();
            let header = served.header(Kind::Install, served.agent.encode());
            stream
                .write_all(install_request(&served, &header).as_bytes())
                .unwrap();
            stream
        })
        .collect();
    // The four heads are read, and their places taken, before the fifth's.
    std::thread::sleep(Duration::from_millis(500));
    let header = served.header(Kind::Install, served.agent.encode());
    let (status, body, _) = install_head(&served, &header);
    assert_eq!((status, body), (503, Vec::new()));
    let unauthorized = Response::Rejected(Rejection::Unauthorized).encode();
    assert_eq!(
        install_head(&served, "Bearer 00").0,
        401,
        "no envelope: refused before the budget"
    );
    let (status, body, _) = exchange(
        served.front.address,
        format!(
            "POST /agents/{}/install HTTP/1.1\r\nHost: node\r\nContent-Length: {}\r\n\r\n",
            served.agent.0,
            vos_wire::abi::cap::MAX_ELF
        )
        .as_bytes(),
    );
    assert_eq!((status, body), (401, unauthorized));
    let elsewhere = operated_header(&signed_operated(
        NodeId([3; 32]),
        &SigningKey::from_bytes(&OPERATOR),
        Kind::Install,
        fresh_nonce(),
        served.now() + 60_000,
        served.agent.encode(),
    ));
    let (status, body, _) = install_head(&served, &elsewhere);
    assert_eq!(
        (status, Response::decode_exact(&body)),
        (
            421,
            Some(Response::Rejected(Rejection::Operator(
                OperatorRefusal::OtherNode
            )))
        )
    );
    assert_eq!(served.node.api_frames(), before, "no node asked");
    // A place given back is taken again.
    drop(held);
    std::thread::sleep(Duration::from_millis(500));
    let mut stream = TcpStream::connect(served.front.address).unwrap();
    stream
        .write_all(install_request(&served, &header).as_bytes())
        .unwrap();
    stream
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let mut answer = [0u8; 1];
    let waited = stream.read(&mut answer);
    assert!(
        waited.is_err(),
        "the body is waited for, not refused: {waited:?}"
    );
}

/// A node that does not answer delays none of the others' requests: its
/// dial holds no lock another request waits on, reads in turn skip it
/// while it is dialed, and the request that had to go to it is answered
/// 503, at once while it is down.
#[test]
fn a_dead_node_delays_no_other_nodes_requests() {
    let served = Served::start(PerAddress::default());
    // A QUIC address where nothing answers: its dial runs to its timeout.
    let silent = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let dead = SigningKey::from_bytes(&[77; 32]).verifying_key().to_bytes();
    let front = Front::start(
        vec![
            (served.node.id().0, Address::Socket(served.socket.clone())),
            (
                dead,
                Address::Quic(silent.local_addr().unwrap().to_string()),
            ),
        ],
        PerAddress::default(),
    );
    let stats = operated_header(&signed_operated(
        NodeId(dead),
        &SigningKey::from_bytes(&OPERATOR),
        Kind::Stats,
        fresh_nonce(),
        served.now() + 60_000,
        Vec::new(),
    ));
    let address = front.address;
    let to_the_dead = std::thread::spawn(move || {
        let started = std::time::Instant::now();
        let (status, _, _) = exchange(
            address,
            &request("GET", "/stats", &[format!("Authorization: {stats}")], b""),
        );
        (status, started.elapsed())
    });
    // Its dial under way for a while.
    std::thread::sleep(Duration::from_secs(1));
    let reads = |count: usize| {
        let started = std::time::Instant::now();
        let reads: Vec<_> = (0..count)
            .map(|_| {
                std::thread::spawn(move || exchange(address, &request("GET", "/time", &[], b"")).0)
            })
            .collect();
        let statuses: Vec<u16> = reads.into_iter().map(|read| read.join().unwrap()).collect();
        (statuses, started.elapsed())
    };
    let (statuses, took) = reads(8);
    let (status, waited) = to_the_dead.join().unwrap();
    assert_eq!(statuses, vec![200; 8]);
    assert!(
        took < Duration::from_secs(2),
        "while it is dialed: {took:?}"
    );
    assert_eq!(status, 503);
    assert!(waited >= Duration::from_secs(5), "its dial ran: {waited:?}");
    // Down after its failed dial: its own requests are answered at once.
    let stats = operated_header(&signed_operated(
        NodeId(dead),
        &SigningKey::from_bytes(&OPERATOR),
        Kind::Stats,
        fresh_nonce(),
        served.now() + 60_000,
        Vec::new(),
    ));
    let started = std::time::Instant::now();
    let (status, _, _) = exchange(
        address,
        &request("GET", "/stats", &[format!("Authorization: {stats}")], b""),
    );
    assert_eq!(status, 503);
    assert!(started.elapsed() < Duration::from_millis(900));
    drop(silent);
}

/// A body past its route's limit is refused 413 by the gateway: no frame
/// reaches the node. The node's time comes through the gateway as the
/// node's clock reads.
#[test]
fn a_refusal_for_size_never_reaches_the_node() {
    let served = Served::start(PerAddress::default());
    let before = served.node.api_frames();
    let path = format!("/agents/{}/install", served.agent.0);
    let header = format!(
        "POST {path} HTTP/1.1\r\nHost: node\r\nContent-Length: {}\r\n\r\n",
        vos_wire::abi::cap::MAX_ELF + vos_api::ENVELOPE + 1
    );
    assert_eq!(exchange(served.front.address, header.as_bytes()).0, 413);
    assert_eq!(served.node.api_frames(), before);
    let (status, body, _) = exchange(served.front.address, &request("GET", "/time", &[], b""));
    assert_eq!(status, 200);
    assert_eq!(u64::decode_exact(&body), Some(served.now()));
    assert_eq!(served.node.api_frames(), before + 1);
}

/// Nodes of one space over a hub, each serving its API's socket, their
/// ingress as `ingress` names it by number.
struct Cluster {
    programs: Programs,
    nodes: Vec<Node>,
    sockets: Vec<PathBuf>,
    _dirs: Vec<tempfile::TempDir>,
}

impl Cluster {
    fn start(count: usize, ingress: impl Fn(u8) -> String) -> Self {
        let programs = Programs::load();
        let dirs: Vec<tempfile::TempDir> =
            (0..count).map(|_| tempfile::tempdir().unwrap()).collect();
        let space = vos_checker::spaces::space(&programs.agent, &dirs, ingress);
        let hub = vos_net::memory::Hub::new(7);
        let clock = Arc::new(AtomicU64::new(vos_node::wall_clock()));
        let nodes: Vec<Node> = dirs
            .iter()
            .map(|dir| {
                let mut config = config(&programs, &clock);
                config.space = Some(space.clone());
                config.peers = Peers::Hub(hub.clone());
                let node = Node::open(dir.path(), config).unwrap();
                node.serve_socket(&dir.path().join("api.sock"), 0o600)
                    .unwrap();
                node
            })
            .collect();
        let sockets = dirs.iter().map(|dir| dir.path().join("api.sock")).collect();
        Self {
            programs,
            nodes,
            sockets,
            _dirs: dirs,
        }
    }

    /// The operator, signing for node `at` and reaching it on its socket.
    fn operator(&self, at: usize) -> Operator {
        Operator::signing(
            &Target::socket(self.sockets[at].clone()),
            SigningKey::from_bytes(&OPERATOR),
            self.nodes[at].id(),
        )
    }

    /// Node `at` as an upstream.
    fn upstream(&self, at: usize) -> ([u8; 32], Address) {
        (
            self.nodes[at].id().0,
            Address::Socket(self.sockets[at].clone()),
        )
    }

    /// The counter's `increment`, as `agent` has it installed.
    fn increment(&self, agent: AgentId) -> MethodId {
        vos_node::client::schema(&Target::socket(self.sockets[0].clone()), agent, COUNTER)
            .unwrap()
            .unwrap()
            .method_id("increment")
            .unwrap()
    }
}

/// A stand-in node on a unix socket at `path` answering every request
/// `NotLeader`, naming `leader`: what a replica answers while its group
/// changes leaders.
fn deposed(runtime: &tokio::runtime::Runtime, path: &std::path::Path, leader: NodeId) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use vos_api::{Event, Framing, Reader, Requests, frame};
    let listener = {
        let _entered = runtime.enter();
        tokio::net::UnixListener::bind(path).unwrap()
    };
    runtime.spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut reader = Reader::requests(Framing::Stream, Requests::All);
                let mut chunk = vec![0u8; 1 << 16];
                let answer = Response::NotLeader {
                    leader: Some(Contact {
                        address: "http://127.0.0.1:1".into(),
                        node: leader,
                    }),
                }
                .encode();
                while let Ok(read @ 1..) = stream.read(&mut chunk).await {
                    reader.push(&chunk[..read]);
                    while let Some(Event::Frame(request)) = reader.event() {
                        let bytes = frame(Framing::Stream, request.kind, request.id, &answer);
                        if stream.write_all(&bytes).await.is_err() {
                            return;
                        }
                    }
                }
            });
        }
    });
}

/// A call the gateway sends to a node that no longer leads is sent on to
/// the leader its `NotLeader` names, which the gateway then learns: the
/// next call goes there at once.
#[test]
fn the_gateway_follows_not_leader_to_the_leader_it_names() {
    let served = Served::start(PerAddress::default());
    let dir = tempfile::tempdir().unwrap();
    let stand_in = dir.path().join("deposed.sock");
    // The stand-in first: the gateway's first request of the turn.
    let front = Front::start(
        vec![
            ([78; 32], Address::Socket(stand_in.clone())),
            (served.node.id().0, Address::Socket(served.socket.clone())),
        ],
        PerAddress::default(),
    );
    deposed(&front.runtime, &stand_in, served.node.id());
    let call = |seed: u8| {
        let body = Client::new(
            &Target::socket(served.socket.clone()),
            SigningKey::from_bytes(&[seed; 32]),
        )
        .call_body(served.agent, 1, COUNTER, served.increment, &1u64.encode())
        .unwrap();
        exchange(
            front.address,
            &request(
                "POST",
                &format!("/agents/{}/calls", served.agent.0),
                &[],
                &body,
            ),
        )
    };
    let (status, body, _) = call(53);
    assert_eq!(status, 200, "{:?}", Response::decode_exact(&body));
    assert!(matches!(
        Response::decode_exact(&body),
        Some(Response::Ran { .. })
    ));
    assert_eq!(front.gateway.sent(), 2, "the stand-in, then the leader");
    let (status, _, _) = call(54);
    assert_eq!(status, 200);
    assert_eq!(front.gateway.sent(), 3, "the leader as learned");
}

/// A client pinning a gateway follows a 421 through it: a gateway knowing
/// only the node that does not hold the agent passes its `Elsewhere` on,
/// the replica's ingress names a second gateway under the same key, and
/// the pin carried across the redirect holds there.
#[test]
fn a_client_pinning_the_gateway_follows_a_421_through_it() {
    let listeners: Vec<std::net::TcpListener> = (0..2)
        .map(|_| std::net::TcpListener::bind("127.0.0.1:0").unwrap())
        .collect();
    let urls: Vec<String> = listeners
        .iter()
        .map(|listener| format!("https://{}", listener.local_addr().unwrap()))
        .collect();
    // Node 1's ingress is the first gateway, node 2's the second.
    let cluster = Cluster::start(2, |number| urls[usize::from(number) - 1].clone());
    let Ok(Response::Created(agent)) = cluster.operator(0).create_agent(Vec::new()) else {
        panic!("an agent on node 1")
    };
    installed(
        cluster
            .operator(0)
            .install(agent, &install_of(COUNTER, &cluster.programs.counter_elf))
            .unwrap(),
    );
    let at_second = Target::socket(cluster.sockets[1].clone());
    wait_until("node 2 learns the agent", || {
        matches!(vos_node::client::agent_info(&at_second, agent), Ok(Some(_)))
    });
    let increment = cluster.increment(agent);
    let tls = || {
        vos_http::tls::server_config(
            &vos_http::tls::IngressTls::NodeKey {
                names: vec!["127.0.0.1".into()],
            },
            &GATEWAY,
        )
        .unwrap()
    };
    let mut listeners = listeners.into_iter();
    let first = Front::start_on(
        listeners.next().unwrap(),
        vec![cluster.upstream(0)],
        PerAddress::default(),
        Some(tls()),
    );
    let second = Front::start_on(
        listeners.next().unwrap(),
        vec![cluster.upstream(1)],
        PerAddress::default(),
        Some(tls()),
    );
    let gateway = SigningKey::from_bytes(&GATEWAY).verifying_key().to_bytes();
    let pinned = Target::new(&urls[1], vos_node::tls::Trust::Gateway(gateway)).unwrap();
    let mut client = Client::new(&pinned, SigningKey::from_bytes(&[13; 32]));
    let answer = client
        .call(agent, COUNTER, increment, &5u64.encode())
        .unwrap();
    assert_eq!(vos_checker::calls::done(answer), 5);
    assert!(
        second.gateway.sent() >= 1,
        "asked first, it passed the 421 on"
    );
    assert!(first.gateway.sent() >= 1, "the redirect reached the first");
}

/// Two nodes of one space behind a gateway: a request to the node that
/// does not hold the agent is sent on to the one that does; a gateway
/// knowing no such node passes the redirect on; an operator's request goes
/// to the one node it is signed for, or is refused when that is none of
/// the gateway's.
#[test]
fn the_gateway_follows_redirects_and_routes_operators_by_their_node() {
    let cluster = Cluster::start(2, |number| {
        format!("http://127.0.0.1:{}", 7000 + u16::from(number))
    });
    let (nodes, sockets) = (&cluster.nodes, &cluster.sockets);
    let operator = |at: usize| cluster.operator(at);
    let Ok(Response::Created(agent)) = operator(0).create_agent(Vec::new()) else {
        panic!("an agent on node 1")
    };
    installed(
        operator(0)
            .install(agent, &install_of(COUNTER, &cluster.programs.counter_elf))
            .unwrap(),
    );
    // Node 2 learns where the agent is.
    let at_second = Target::socket(sockets[1].clone());
    wait_until("node 2 learns the agent", || {
        matches!(vos_node::client::agent_info(&at_second, agent), Ok(Some(_)))
    });
    let both = vec![cluster.upstream(1), cluster.upstream(0)];
    let front = Front::start(both, PerAddress::default());
    let url = format!("http://{}", front.address);
    let mut client = Client::new(
        &Target::loopback(&url).unwrap(),
        SigningKey::from_bytes(&[8; 32]),
    );
    let increment = cluster.increment(agent);
    for by in 1..=3u64 {
        let answer = client
            .call(agent, COUNTER, increment, &by.encode())
            .unwrap();
        assert!(matches!(answer, Response::Ran { .. }), "{answer:?}");
    }
    // A gateway knowing only node 2 passes the redirect on.
    let alone = Front::start(vec![cluster.upstream(1)], PerAddress::default());
    let call = Client::new(
        &Target::socket(sockets[0].clone()),
        SigningKey::from_bytes(&[9; 32]),
    )
    .call_body(agent, 1, COUNTER, increment, &1u64.encode())
    .unwrap();
    let (status, body, _) = exchange(
        alone.address,
        &request("POST", &format!("/agents/{}/calls", agent.0), &[], &call),
    );
    assert_eq!(status, 421);
    assert!(matches!(
        Response::decode_exact(&body),
        Some(Response::Elsewhere { .. })
    ));
    // An operator's request signed for node 2 runs on node 2; one signed
    // for a node behind no upstream is refused by the gateway.
    let through = |node: NodeId| {
        Operator::signing(
            &Target::loopback(&url).unwrap(),
            SigningKey::from_bytes(&OPERATOR),
            node,
        )
    };
    let Ok(Response::Created(created)) = through(nodes[1].id()).create_agent(Vec::new()) else {
        panic!("an agent on node 2")
    };
    assert_eq!(
        vos_wire::peer::CreationRecord::creator_of(created),
        2,
        "created by node 2"
    );
    let sent = front.gateway.sent();
    assert_eq!(
        through(NodeId([3; 32])).stats().unwrap(),
        Response::Rejected(Rejection::Operator(OperatorRefusal::OtherNode))
    );
    assert_eq!(front.gateway.sent(), sent, "no node asked");
}

/// A client pinning the gateway's own-key HTTPS calls through it: the node
/// key `GET /` answers is not compared with the gateway's, and the pin
/// holds.
#[test]
fn a_client_pinning_the_gateway_calls_through_it() {
    let served = Served::start(PerAddress::default());
    let tls = vos_http::tls::server_config(
        &vos_http::tls::IngressTls::NodeKey {
            names: vec!["127.0.0.1".into()],
        },
        &GATEWAY,
    )
    .unwrap();
    let front = Front::start_with(
        vec![(served.node.id().0, Address::Socket(served.socket.clone()))],
        PerAddress::default(),
        Some(tls),
    );
    let gateway = SigningKey::from_bytes(&GATEWAY).verifying_key().to_bytes();
    let url = format!("https://{}", front.address);
    let pinned = Target::new(&url, vos_node::tls::Trust::Gateway(gateway)).unwrap();
    assert_eq!(
        vos_node::client::node_id(&pinned).unwrap(),
        served.node.id()
    );
    // Pinned as a node instead, the gateway's key is not the node's.
    let as_node = Target::new(&url, vos_node::tls::Trust::NodeKey(gateway)).unwrap();
    assert!(vos_node::client::node_id(&as_node).is_err());
    let mut client = Client::new(&pinned, SigningKey::from_bytes(&[12; 32]));
    let mut total = 0;
    for by in 1..=3u64 {
        total += by;
        let answer = client
            .call(served.agent, COUNTER, served.increment, &by.encode())
            .unwrap();
        assert_eq!(vos_checker::calls::done(answer), total);
    }
}
