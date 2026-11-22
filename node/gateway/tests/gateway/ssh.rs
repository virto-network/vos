//! The `vos-api` subsystem on the gateway's SSH port, under an ephemeral
//! key: the relay set relayed and the node's time through it, a session's
//! calls among them; any other kind refused `NotRelayed`, the channel
//! closed and no node asked; a node gone answered `Unavailable` with the
//! channel kept; at most 16 requests in flight a channel; each frame
//! marked with its port's transport; and a flood of junk proven calls
//! held to the port's caps, answered `Busy` past them, while a member's
//! calls are served.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use russh::keys::{PublicKeyOrCertificate, ssh_key};
use russh::{ChannelMsg, client};
use vos_abi::ids::{AgentId, InstanceId, MethodId};
use vos_abi::{Decode, Encode};
use vos_api::{FRAME_ERROR, FrameError, Framing, Kind, frame};
use vos_checker::programs::Programs;
use vos_gateway::Gateway;
use vos_gateway::limits::{Limits, PerAddress};
use vos_gateway::ssh::Port;
use vos_gateway::upstream::{Address, Upstream};
use vos_node::Node;
use vos_node::client::{Client, Operator, Target, signed_query};
use vos_wire::ingress::{Consistency, Rejection, Response};

use super::{COUNTER, GATEWAY, OPERATOR, config};

struct AcceptAll;

impl client::Handler for AcceptAll {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        _key: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        Ok(true)
    }
}

/// A node with the counter, its socket, and the clock it reads.
struct Served {
    node: Node,
    socket: PathBuf,
    clock: Arc<AtomicU64>,
    _dir: tempfile::TempDir,
}

fn served() -> Served {
    let programs = Programs::load();
    let dir = tempfile::tempdir().unwrap();
    let clock = Arc::new(AtomicU64::new(vos_node::wall_clock()));
    let node = Node::open(dir.path(), config(&programs, &clock)).unwrap();
    let socket = dir.path().join("api.sock");
    node.serve_socket(&socket, 0o600).unwrap();
    Served {
        node,
        socket,
        clock,
        _dir: dir,
    }
}

impl Served {
    /// A new agent with the counter installed, by the operator: its id,
    /// its identity and the counter's `value`.
    async fn counter(&self) -> (AgentId, [u8; 32], MethodId) {
        let target = Target::socket(self.socket.clone());
        let operator =
            Operator::signing(&target, SigningKey::from_bytes(&OPERATOR), self.node.id());
        tokio::task::spawn_blocking(move || {
            let programs = Programs::load();
            let Ok(Response::Created(agent)) = operator.create_agent(Vec::new()) else {
                panic!("an agent")
            };
            vos_checker::calls::installed(
                operator
                    .install(
                        agent,
                        &vos_checker::calls::install_of(COUNTER, &programs.counter_elf),
                    )
                    .unwrap(),
            );
            let client = Client::new(&target, SigningKey::from_bytes(&[9; 32]));
            let identity = client.identity(agent).unwrap();
            let value = client
                .schema(agent, COUNTER)
                .unwrap()
                .unwrap()
                .method_id("value")
                .unwrap();
            (agent, identity, value)
        })
        .await
        .unwrap()
    }
}

/// An SSH port relaying to node `node` at `socket`, counted and capped as
/// `port`, under the host key of `seed`'s bytes, and its address.
async fn ssh_port(node: [u8; 32], socket: PathBuf, port: Port, seed: u8) -> std::net::SocketAddr {
    let gateway = Arc::new(Gateway::new(vec![Upstream::new(
        node,
        Address::Socket(socket),
        GATEWAY,
    )]));
    let host_key =
        ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[seed; 32]));
    let server = vos_gateway::ssh::server(host_key, gateway, port, &vos_gateway::ssh::Placeholder);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.serve_on(listener).await;
    });
    address
}

/// An SSH port relaying to the node at `socket`, and its address.
async fn port(key: [u8; 32], socket: PathBuf) -> std::net::SocketAddr {
    port_marked(key, socket, vos_api::Mark::Clearnet).await
}

/// An SSH port relaying to the node at `socket`, marking each frame
/// `mark`, and its address.
async fn port_marked(key: [u8; 32], socket: PathBuf, mark: vos_api::Mark) -> std::net::SocketAddr {
    port_limited(key, socket, mark, PerAddress::default()).await
}

/// An SSH port relaying to the node at `socket`, marking each frame
/// `mark`, each address limited to `per`, and its address.
async fn port_limited(
    key: [u8; 32],
    socket: PathBuf,
    mark: vos_api::Mark,
    per: PerAddress,
) -> std::net::SocketAddr {
    let port = Port::new(mark, Limits::new(per), vos_gateway::caps::Caps::none());
    ssh_port(key, socket, port, 3).await
}

/// The subsystem's channel, under an ephemeral key.
async fn channel(address: std::net::SocketAddr) -> russh::Channel<client::Msg> {
    channel_from(address, std::net::Ipv4Addr::LOCALHOST)
        .await
        .unwrap()
}

/// The same from the loopback address `from`: each a circuit of its own
/// to a port that counts addresses as circuits. `None` when the port
/// takes no more connections now.
async fn channel_from(
    address: std::net::SocketAddr,
    from: std::net::Ipv4Addr,
) -> Option<russh::Channel<client::Msg>> {
    static DRAWN: AtomicU64 = AtomicU64::new(1);
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&vos_node::wall_clock().to_le_bytes());
    seed[8..16].copy_from_slice(&DRAWN.fetch_add(1, Ordering::Relaxed).to_le_bytes());
    let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&seed));
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind((from, 0).into()).unwrap();
    let stream = socket.connect(address).await.ok()?;
    let mut handle = client::connect_stream(Arc::new(client::Config::default()), stream, AcceptAll)
        .await
        .ok()?;
    let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
    assert!(
        handle
            .authenticate_publickey("anyone", key)
            .await
            .unwrap()
            .success()
    );
    let mut channel = handle.channel_open_session().await.ok()?;
    channel
        .request_subsystem(true, vos_gateway::ssh::SUBSYSTEM)
        .await
        .ok()?;
    // A bound on the wait, which a loaded host may stretch.
    let reply = tokio::time::timeout(Duration::from_secs(30), channel.wait())
        .await
        .ok()?;
    assert!(matches!(reply, Some(ChannelMsg::Success)), "{reply:?}");
    // The connection lives as long as its channel's test.
    std::mem::forget(handle);
    Some(channel)
}

/// Frames from the channel's bytes, as they come; `None` once it closed.
struct Answers {
    buffer: Vec<u8>,
}

impl Answers {
    async fn next(
        &mut self,
        channel: &mut russh::Channel<client::Msg>,
    ) -> Option<(u16, u64, Vec<u8>)> {
        loop {
            let header = vos_api::Framing::Stream.header();
            if self.buffer.len() >= header {
                let length = u32::from_le_bytes(self.buffer[..4].try_into().unwrap()) as usize;
                if self.buffer.len() >= 4 + length {
                    let kind = u16::from_le_bytes(self.buffer[4..6].try_into().unwrap());
                    assert_eq!(self.buffer[6], 0, "an answer is unmarked");
                    let id = u64::from_le_bytes(self.buffer[7..15].try_into().unwrap());
                    let body = self.buffer[header..4 + length].to_vec();
                    self.buffer.drain(..4 + length);
                    return Some((kind, id, body));
                }
            }
            match tokio::time::timeout(Duration::from_secs(30), channel.wait())
                .await
                .ok()?
            {
                Some(ChannelMsg::Data { data }) => self.buffer.extend_from_slice(&data),
                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => return None,
                Some(_) => {}
            }
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_relay_set_is_relayed_and_any_other_kind_refused() {
    let served = served();
    let address = port(served.node.id().0, served.socket.clone()).await;
    let mut channel = channel(address).await;
    let mut answers = Answers { buffer: Vec::new() };
    channel
        .data(&frame(Framing::Stream, Kind::Time as u16, 1, &[])[..])
        .await
        .unwrap();
    let (kind, id, body) = answers.next(&mut channel).await.unwrap();
    assert_eq!((kind, id), (Kind::Time as u16, 1));
    assert_eq!(
        u64::decode_exact(&body),
        Some(served.clock.load(Ordering::SeqCst))
    );
    channel
        .data(&frame(Framing::Stream, Kind::NodeKey as u16, 2, &[])[..])
        .await
        .unwrap();
    assert_eq!(
        answers.next(&mut channel).await,
        Some((Kind::NodeKey as u16, 2, served.node.id().encode()))
    );
    let asked = served.node.probes().api_frames();
    // A workflow read's header alone: refused before its body, no node
    // asked.
    let header = vos_api::Header::of(Framing::Stream, Kind::Workflow as u16, 3, 100);
    channel
        .data(&header.encode(Framing::Stream)[..])
        .await
        .unwrap();
    let (kind, id, body) = answers.next(&mut channel).await.unwrap();
    assert_eq!((kind, id), (FRAME_ERROR, 3));
    assert_eq!(
        FrameError::decode_exact(&body),
        Some(FrameError::NotRelayed)
    );
    assert_eq!(answers.next(&mut channel).await, None, "the channel closes");
    assert_eq!(served.node.probes().api_frames(), asked);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_gone_is_unavailable_and_the_channel_goes_on() {
    let dir = tempfile::tempdir().unwrap();
    let address = port([7; 32], dir.path().join("none.sock")).await;
    let mut channel = channel(address).await;
    let mut answers = Answers { buffer: Vec::new() };
    for id in [1, 2] {
        channel
            .data(&frame(Framing::Stream, Kind::Time as u16, id, &[])[..])
            .await
            .unwrap();
        let (kind, answered, body) = answers.next(&mut channel).await.unwrap();
        assert_eq!((kind, answered), (FRAME_ERROR, id));
        assert_eq!(
            FrameError::decode_exact(&body),
            Some(FrameError::Unavailable)
        );
    }
}

/// Sixteen requests in flight on one channel: the seventeenth is read only
/// as one of them ends.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sixteen_requests_in_flight_a_channel() {
    sixteen_in_flight(vos_api::Mark::Clearnet, PerAddress::default()).await;
}

/// The same on a port whose addresses are an onion's circuits: a channel's
/// requests in flight are counted apart from its circuit's channels, so a
/// circuit's one channel carries its sixteen too.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sixteen_requests_in_flight_a_channel_of_a_circuit() {
    sixteen_in_flight(vos_api::Mark::Onion, vos_gateway::config::PER_CIRCUIT).await;
}

async fn sixteen_in_flight(mark: vos_api::Mark, per: PerAddress) {
    let served = served();
    let (agent, identity, value) = served.counter().await;
    let address = port_limited(served.node.id().0, served.socket.clone(), mark, per).await;
    let mut channel = channel(address).await;
    let mut answers = Answers { buffer: Vec::new() };
    // A query at a floor never reached: answered `Behind` after 5 s.
    let slow = signed_query(
        &identity,
        &SigningKey::from_bytes(&[9; 32]),
        served.clock.load(Ordering::SeqCst) + 60_000,
        Consistency::Applied { at: u64::MAX },
        COUNTER,
        value,
        Vec::new(),
    );
    let asked = Instant::now();
    for id in 1..=16 {
        channel
            .data(
                &frame(
                    Framing::Stream,
                    Kind::Query as u16,
                    id,
                    &(agent, slow.clone()).encode(),
                )[..],
            )
            .await
            .unwrap();
    }
    channel
        .data(&frame(Framing::Stream, Kind::Time as u16, 17, &[])[..])
        .await
        .unwrap();
    let (kind, _, body) = answers.next(&mut channel).await.unwrap();
    assert_eq!(kind, Kind::Query as u16, "a slow one ends first");
    assert_eq!(
        Response::decode_exact(&body),
        Some(Response::Rejected(Rejection::Behind))
    );
    assert!(asked.elapsed() >= Duration::from_secs(4));
    let mut ids = Vec::new();
    while ids.len() < 16 {
        ids.push(answers.next(&mut channel).await.unwrap().1);
    }
    assert!(ids.contains(&17));
}

/// The subsystem marks every frame it relays with its port's transport,
/// whatever the client marked: an onion-marked query over the clearnet
/// port to the onion-only gated agent is refused `OnionOnly`; over a port
/// marking as the onion service's would, it is answered.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_relay_marks_each_frame_with_its_port() {
    use vos_api::Mark;
    use vos_wire::ingress::AdmissionRefusal;
    const GATED: InstanceId = InstanceId(1);
    let served = served();
    let target = Target::socket(served.socket.clone());
    let operator = Operator::signing(&target, SigningKey::from_bytes(&OPERATOR), served.node.id());
    let (gated, identity) = tokio::task::spawn_blocking(move || {
        let Ok(Response::Created(agent)) = operator.create_agent(Vec::new()) else {
            panic!("an agent")
        };
        let elf = vos_checker::programs::package("gated");
        vos_checker::calls::installed(
            operator
                .install(agent, &vos_checker::calls::install_of(GATED, &elf))
                .unwrap(),
        );
        let identity = Client::new(&target, SigningKey::from_bytes(&[1; 32]))
            .identity(agent)
            .unwrap();
        (agent, identity)
    })
    .await
    .unwrap();
    let query = signed_query(
        &identity,
        &SigningKey::from_bytes(&[72; 32]),
        served.clock.load(Ordering::SeqCst) + 10_000,
        Consistency::Applied { at: 0 },
        GATED,
        vos_abi::ids::MethodId(vos_abi::ids::derive_id("vos/method/", "count")),
        Vec::new(),
    );
    let body = (gated, query).encode();
    for mark in [Mark::Clearnet, Mark::Onion] {
        let address = port_marked(served.node.id().0, served.socket.clone(), mark).await;
        let mut channel = channel(address).await;
        let mut answers = Answers { buffer: Vec::new() };
        channel
            .data(&vos_api::marked(Framing::Stream, Kind::Query as u16, Mark::Onion, 1, &body)[..])
            .await
            .unwrap();
        let (kind, id, answer) = answers.next(&mut channel).await.unwrap();
        assert_eq!((kind, id), (Kind::Query as u16, 1));
        let answer = Response::decode_exact(&answer).unwrap();
        match mark {
            Mark::Onion => assert!(matches!(answer, Response::Ran { .. }), "{answer:?}"),
            _ => assert_eq!(
                answer,
                Response::Rejected(Rejection::Admission(AdmissionRefusal::OnionOnly))
            ),
        }
    }
}

/// A node behind a stand-in that holds each proven call for `hold` before
/// it answers `Malformed`, as a node verifying a proof holds it, and passes
/// every other request to the node: the proven calls it holds at once, at
/// most.
struct Verifying {
    socket: PathBuf,
    held: Arc<AtomicU64>,
    most: Arc<AtomicU64>,
    proven: Arc<AtomicU64>,
    _dir: tempfile::TempDir,
}

async fn verifying(node: [u8; 32], socket: PathBuf, hold: Duration) -> Verifying {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use vos_api::{Event, Reader, Requests};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("verifying.sock");
    let listener = tokio::net::UnixListener::bind(&path).unwrap();
    let upstream = Upstream::new(node, Address::Socket(socket), [42; 32]);
    let (held, most, proven) = Default::default();
    let verifying = Verifying {
        socket: path,
        held: Arc::clone(&held),
        most: Arc::clone(&most),
        proven: Arc::clone(&proven),
        _dir: dir,
    };
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let (mut reading, writing) = stream.into_split();
            let writing = Arc::new(tokio::sync::Mutex::new(writing));
            let (upstream, held, most, proven) = (
                Arc::clone(&upstream),
                Arc::clone(&held),
                Arc::clone(&most),
                Arc::clone(&proven),
            );
            tokio::spawn(async move {
                let mut reader = Reader::requests(Framing::Stream, Requests::All);
                let mut chunk = vec![0u8; 64 << 10];
                while let Ok(read @ 1..) = reading.read(&mut chunk).await {
                    reader.push(&chunk[..read]);
                    while let Some(Event::Frame(request)) = reader.event() {
                        let (upstream, writing) = (Arc::clone(&upstream), Arc::clone(&writing));
                        let (held, most, proven) =
                            (Arc::clone(&held), Arc::clone(&most), Arc::clone(&proven));
                        tokio::spawn(async move {
                            let (kind, body) = if request.kind == Kind::Credentialed as u16 {
                                proven.fetch_add(1, Ordering::SeqCst);
                                let now = held.fetch_add(1, Ordering::SeqCst) + 1;
                                most.fetch_max(now, Ordering::SeqCst);
                                tokio::time::sleep(hold).await;
                                held.fetch_sub(1, Ordering::SeqCst);
                                (
                                    request.kind,
                                    Response::Rejected(Rejection::Malformed).encode(),
                                )
                            } else {
                                upstream
                                    .request(request.kind, request.mark, &request.body)
                                    .await
                                    .unwrap()
                            };
                            let bytes = frame(Framing::Stream, kind, request.id, &body);
                            let _ = writing.lock().await.write_all(&bytes).await;
                        });
                    }
                }
            });
        }
    });
    verifying
}

/// A flood of well-formed junk proven calls, a device proof's size each,
/// from eight connections at once through a port capped as the onion's: at
/// most the port's proven calls held behind it at once, the rest waiting
/// for a place with their bodies unread; a connection past its own proven
/// calls answered `Busy` and closed before its body is read; every place
/// given back once answered. Meanwhile a member's queries, a session's
/// call and the member's own proven call, on a connection of its own, are
/// all answered: the proven call reaches the node in its turn.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_flood_of_junk_proofs_is_held_to_the_caps_and_members_are_served() {
    use vos_gateway::caps::{Caps, PerPort};
    let served = served();
    let (agent, identity, value) = served.counter().await;
    let standing = verifying(
        served.node.id().0,
        served.socket.clone(),
        Duration::from_millis(500),
    )
    .await;
    let caps = Caps::new(PerPort {
        proven: 4,
        proven_per_connection: 2,
        // Every test connection is from one address.
        proven_per_circuit: 1_000,
        waiting_per_circuit: 1_000,
        agent_rate: 1_000,
        agent_burst: 1_000,
    });
    let port = Port::new(
        vos_api::Mark::Onion,
        Limits::new(PerAddress::default()),
        Arc::clone(&caps),
    );
    let address = ssh_port(served.node.id().0, standing.socket.clone(), port, 3).await;
    // Junk in shape: a credentialed call whose proof is 900 KB of noise.
    let junk = |at: u64| {
        let call = vos_wire::ingress::Credentialed {
            instance: COUNTER,
            method: value,
            arguments: Vec::new(),
            nonce: [at as u8; 16],
            expires_ms: served.clock.load(Ordering::SeqCst) + 60_000,
            format: 0,
            claim: vec![5; 64],
            proof: (0..900_000).map(|byte| (byte as u64 ^ at) as u8).collect(),
        };
        frame(
            Framing::Stream,
            Kind::Credentialed as u16,
            at,
            &(agent, call).encode(),
        )
    };
    const CONNECTIONS: u64 = 8;
    const FLOOD: u64 = 2;
    let mut floods = Vec::new();
    for connection in 0..CONNECTIONS {
        let mut channel = channel(address).await;
        let frames: Vec<Vec<u8>> = (1..=FLOOD).map(|at| junk(connection * 100 + at)).collect();
        floods.push(tokio::spawn(async move {
            for bytes in &frames {
                channel.data(&bytes[..]).await.unwrap();
            }
            let mut answers = Answers { buffer: Vec::new() };
            for _ in 0..FLOOD {
                let (kind, _, body) = answers.next(&mut channel).await.unwrap();
                assert_eq!(kind, Kind::Credentialed as u16);
                assert_eq!(
                    Response::decode_exact(&body),
                    Some(Response::Rejected(Rejection::Malformed)),
                    "each reaches the node in its turn"
                );
            }
        }));
    }
    // A connection pipelining past its own proven calls, on a port whose
    // own places are many and whose node holds each proof 3 s: its third
    // is answered `Busy` from its header, and the channel closed.
    let slow = verifying(
        served.node.id().0,
        served.socket.clone(),
        Duration::from_secs(3),
    )
    .await;
    let roomy = Caps::new(PerPort {
        proven: 100,
        proven_per_connection: 2,
        proven_per_circuit: 1_000,
        waiting_per_circuit: 1_000,
        agent_rate: 1_000,
        agent_burst: 1_000,
    });
    let port = Port::new(
        vos_api::Mark::Onion,
        Limits::new(PerAddress::default()),
        Arc::clone(&roomy),
    );
    let roomy_address = ssh_port(served.node.id().0, slow.socket.clone(), port, 4).await;
    let mut greedy = channel(roomy_address).await;
    for at in 1..=3 {
        greedy.data(&junk(900 + at)[..]).await.unwrap_or(());
    }
    // A member, on a connection of its own, while the flood is held.
    let mut member = channel(address).await;
    let mut answers = Answers { buffer: Vec::new() };
    let key = SigningKey::from_bytes(&[9; 32]);
    let started = Instant::now();
    for id in 1..=4 {
        let query = signed_query(
            &identity,
            &key,
            served.clock.load(Ordering::SeqCst) + 60_000,
            Consistency::Applied { at: 0 },
            COUNTER,
            value,
            Vec::new(),
        );
        member
            .data(
                &frame(
                    Framing::Stream,
                    Kind::Query as u16,
                    id,
                    &(agent, query).encode(),
                )[..],
            )
            .await
            .unwrap();
        let (kind, answered, body) = answers.next(&mut member).await.unwrap();
        assert_eq!((kind, answered), (Kind::Query as u16, id));
        assert!(
            matches!(Response::decode_exact(&body), Some(Response::Ran { .. })),
            "{body:?}"
        );
    }
    let session = vos_abi::ids::Session {
        key: key.verifying_key().to_bytes(),
        name: [3; 16],
        t0: served.clock.load(Ordering::SeqCst),
    };
    let increment = vos_abi::ids::MethodId(vos_abi::ids::derive_id("vos/method/", "increment"));
    let call = vos_node::client::signed_call(
        &identity,
        &key,
        session,
        1,
        COUNTER,
        increment,
        1u64.encode(),
    );
    member
        .data(
            &frame(
                Framing::Stream,
                Kind::Call as u16,
                9,
                &(agent, call).encode(),
            )[..],
        )
        .await
        .unwrap();
    let (kind, answered, body) = answers.next(&mut member).await.unwrap();
    assert_eq!((kind, answered), (Kind::Call as u16, 9));
    assert!(
        matches!(Response::decode_exact(&body), Some(Response::Ran { .. })),
        "{:?}",
        Response::decode_exact(&body)
    );
    // The member's own proven call, waiting its turn behind the flood.
    member.data(&junk(7_000)[..]).await.unwrap();
    let (kind, _, body) = answers.next(&mut member).await.unwrap();
    assert_eq!(kind, Kind::Credentialed as u16);
    assert_eq!(
        Response::decode_exact(&body),
        Some(Response::Rejected(Rejection::Malformed)),
        "the member's proven call reached the node"
    );
    let member_took = started.elapsed();
    for flood in floods {
        flood.await.unwrap();
    }
    let mut answers = Answers { buffer: Vec::new() };
    let mut greedy_answers = Vec::new();
    while let Some((_, id, body)) = answers.next(&mut greedy).await {
        greedy_answers.push((id, Response::decode_exact(&body).unwrap()));
    }
    assert!(
        greedy_answers.contains(&(903, Response::Busy)),
        "{greedy_answers:?}"
    );
    assert!(greedy_answers.len() <= 3, "the channel closed");
    assert!(
        standing.most.load(Ordering::SeqCst) <= 4,
        "at most the port's proven calls held at once: {}",
        standing.most.load(Ordering::SeqCst)
    );
    assert_eq!(roomy.refused().connection, 1);
    assert_eq!(caps.proven(), 0, "every place given back");
    assert!(
        member_took < Duration::from_secs(20),
        "the member waited {member_took:?}"
    );
    assert_eq!(standing.held.load(Ordering::SeqCst), 0);
    assert_eq!(
        standing.proven.load(Ordering::SeqCst),
        CONNECTIONS * FLOOD + 1,
        "every proven call within its connection's reached the node"
    );
}

/// The SSH server takes the connections its port names, the handshake
/// included (`[onion] ssh_connections`, `ssh_connections`): past them a
/// connection waits for one to close.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_port_takes_the_ssh_connections_its_file_names() {
    let served = served();
    let port = Port::new(
        vos_api::Mark::Onion,
        Limits::new(PerAddress::default()),
        vos_gateway::caps::Caps::none(),
    )
    .with_connections(Some(1));
    let address = ssh_port(served.node.id().0, served.socket.clone(), port, 6).await;
    let first = channel(address).await;
    let second = tokio::time::timeout(
        Duration::from_secs(2),
        channel_from(address, std::net::Ipv4Addr::LOCALHOST),
    )
    .await;
    assert!(second.is_err(), "a second connection past the port's one");
    drop(first);
}

/// Circuits holding the onion's proven-call places with headers alone,
/// their bodies never sent, each channel opened again once closed, cannot
/// starve a member: a circuit's waiters are its own (one at a time, its
/// places taken before the port's), and a body that falls behind its pace
/// gives its places back about `PROGRESS` on. The member's proven call, on
/// a circuit of its own, reaches the node within one turn of the queue.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn headers_alone_hold_no_members_proven_call_back() {
    starved(Held::Header).await;
}

/// The same with each body trickled a byte a second: kept coming, but
/// behind its pace.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn trickled_bodies_hold_no_members_proven_call_back() {
    starved(Held::Trickled).await;
}

/// The same with each body the smallest large one, sent evenly over the
/// most a large body may take: a pace that allowed any body that long
/// would hold every place that long. Its length at the slowest rate is
/// its time, so it falls behind within a few seconds.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn small_bodies_at_the_longest_pace_hold_no_members_proven_call_back() {
    starved(Held::Paced).await;
}

#[derive(Clone, Copy, PartialEq)]
enum Held {
    Header,
    Trickled,
    Paced,
}

async fn starved(held: Held) {
    use vos_gateway::caps::{Caps, PerPort};
    let served = served();
    let (agent, _, value) = served.counter().await;
    let standing = verifying(
        served.node.id().0,
        served.socket.clone(),
        Duration::from_millis(100),
    )
    .await;
    let caps = Caps::new(PerPort {
        proven: 4,
        proven_per_connection: 2,
        proven_per_circuit: 2,
        waiting_per_circuit: 1,
        agent_rate: 1_000,
        agent_burst: 1_000,
    });
    let port = Port::new(
        vos_api::Mark::Onion,
        Limits::new(PerAddress {
            connections: 8,
            in_flight: 16,
            rate: 1_000,
            burst: 1_000,
        }),
        Arc::clone(&caps),
    );
    let address = ssh_port(served.node.id().0, standing.socket.clone(), port, 5).await;
    // The smallest large body for `Held::Paced`, a device proof's size
    // otherwise.
    let proof = match held {
        Held::Paced => Kind::Call.limit() as usize + 4_096,
        _ => 300_000,
    };
    let junk = |at: u64| {
        let call = vos_wire::ingress::Credentialed {
            instance: COUNTER,
            method: value,
            arguments: Vec::new(),
            nonce: [at as u8; 16],
            expires_ms: served.clock.load(Ordering::SeqCst) + 60_000,
            format: 0,
            claim: vec![5; 64],
            proof: vec![at as u8; proof],
        };
        frame(
            Framing::Stream,
            Kind::Credentialed as u16,
            at,
            &(agent, call).encode(),
        )
    };
    let header = vos_api::Framing::Stream.header();
    // Five circuits, two channels each, every one sending a header alone
    // and holding it until the gateway closes it: ten calls for the port's
    // four places and at most one waiter a circuit, so some circuit's
    // second is refused whatever the order.
    let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mut holders = Vec::new();
    for circuit in 0..5u8 {
        for lane in 0..2u64 {
            let (stop, bytes) = (
                Arc::clone(&stop),
                junk(1_000 + u64::from(circuit) * 10 + lane),
            );
            holders.push(tokio::spawn(async move {
                let from = std::net::Ipv4Addr::new(127, 0, 1, 10 + circuit);
                while !stop.load(Ordering::SeqCst) {
                    let Some(mut channel) = channel_from(address, from).await else {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                        continue;
                    };
                    if channel.data(&bytes[..header]).await.is_err() {
                        continue;
                    }
                    match held {
                        Held::Header => {}
                        // Past the whole body's deadline either way.
                        Held::Trickled => {
                            for byte in bytes[header..].iter().take(60) {
                                tokio::time::sleep(Duration::from_secs(1)).await;
                                if channel.data(&[*byte][..]).await.is_err() {
                                    break;
                                }
                            }
                        }
                        // A thirtieth of the body a second, from a first
                        // part at once: within `LARGE_DEADLINE`'s pace.
                        Held::Paced => {
                            let body = &bytes[header..];
                            let part = body.len().div_ceil(30);
                            for chunk in body.chunks(part) {
                                if channel.data(chunk).await.is_err() {
                                    break;
                                }
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                        }
                    }
                    let mut answers = Answers { buffer: Vec::new() };
                    while answers.next(&mut channel).await.is_some() {}
                }
            }));
        }
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    let mut member = channel_from(address, std::net::Ipv4Addr::new(127, 0, 2, 1))
        .await
        .unwrap();
    let started = Instant::now();
    member.data(&junk(7_000)[..]).await.unwrap();
    let mut answers = Answers { buffer: Vec::new() };
    let answered = tokio::time::timeout(Duration::from_secs(90), answers.next(&mut member))
        .await
        .expect("an answer")
        .expect("the channel open");
    let took = started.elapsed();
    stop.store(true, Ordering::SeqCst);
    assert_eq!(answered.0, Kind::Credentialed as u16);
    assert_eq!(
        Response::decode_exact(&answered.2),
        Some(Response::Rejected(Rejection::Malformed)),
        "the member's proven call reached the node"
    );
    assert!(took < Duration::from_secs(20), "the member waited {took:?}");
    assert!(caps.refused().waiting > 0, "{:?}", caps.refused());
    for holder in holders {
        holder.abort();
    }
}

/// The onion's servers, each circuit's channels limited to `connections`
/// and its streams to `streams`, taking the streams handed to them as
/// arti's circuits hand them.
#[cfg(feature = "tor")]
fn onion(
    node: [u8; 32],
    socket: &std::path::Path,
    connections: usize,
    streams: usize,
) -> (vos_gateway::served::Front, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let text = format!(
        r#"
key = "{dir}/gateway.key"
http = "127.0.0.1:0"
nodes = [{{ key = "{node}", address = "unix:{socket}" }}]
ssh = "127.0.0.1:0"
ssh_host_key = "{dir}/ssh_host_key"

[onion]
circuit_connections = {connections}
circuit_streams = {streams}
"#,
        dir = dir.path().display(),
        node = hex::encode(node),
        socket = socket.display(),
    );
    let config: vos_gateway::config::Config = toml::from_str(&text).unwrap();
    let gateway = config.gateway(GATEWAY).unwrap();
    let front = vos_gateway::served::front(
        &config,
        config.onion.as_ref().unwrap(),
        gateway,
        &vos_gateway::ssh::Placeholder,
    )
    .unwrap();
    (front, dir)
}

/// An SSH connection under an ephemeral key over a stream to the onion's
/// port 22 on circuit `circuit`.
#[cfg(feature = "tor")]
async fn over_circuit(
    front: &vos_gateway::served::Front,
    circuit: u32,
) -> Result<client::Handle<AcceptAll>, russh::Error> {
    let (ours, theirs) = tokio::io::duplex(1 << 20);
    front
        .onion
        .serve(theirs, circuit, vos_gateway::circuits::SSH)
        .await;
    let mut handle =
        client::connect_stream(Arc::new(client::Config::default()), ours, AcceptAll).await?;
    let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&seed_of(
        circuit,
    )));
    let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
    assert!(
        handle
            .authenticate_publickey("anyone", key)
            .await?
            .success()
    );
    Ok(handle)
}

/// An SSH key of the connection's own.
#[cfg(feature = "tor")]
fn seed_of(circuit: u32) -> [u8; 32] {
    let mut seed = [7u8; 32];
    seed[..4].copy_from_slice(&circuit.to_le_bytes());
    seed
}

/// A `vos-api` subsystem channel asked for on `handle`: one the gateway
/// serves no channel closes at once.
#[cfg(feature = "tor")]
async fn subsystem(handle: &client::Handle<AcceptAll>) -> russh::Channel<client::Msg> {
    let channel = handle.channel_open_session().await.unwrap();
    channel
        .request_subsystem(true, vos_gateway::ssh::SUBSYSTEM)
        .await
        .unwrap();
    channel
}

/// A terminal's text, its escape sequences dropped.
#[cfg(feature = "tor")]
fn text(bytes: &[u8]) -> String {
    let mut text = String::new();
    let mut chars = String::from_utf8_lossy(bytes).into_owned();
    chars.push(' ');
    let mut chars = chars.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\x1b' {
            text.push(c);
            continue;
        }
        match chars.next() {
            // CSI: up to its final byte.
            Some('[') => {
                for c in chars.by_ref() {
                    if ('@'..='~').contains(&c) {
                        break;
                    }
                }
            }
            // OSC, APC, DCS: up to BEL or ST.
            Some(']' | '_' | 'P') => {
                while let Some(c) = chars.next() {
                    if c == '\x07' || (c == '\x1b' && chars.next_if_eq(&'\\').is_some()) {
                        break;
                    }
                }
            }
            _ => {}
        }
    }
    text
}

/// s4's screens over the onion: a stream on a circuit, handed to the
/// onion's SSH server with its circuit's address, serves the gateway's own
/// screen (its file names no demo) on a terminal and, on the same connection, the `vos-api` subsystem marking
/// onion, which the onion-only gated agent answers. Each circuit holds its
/// own channels and their requests (two places here: past them a request
/// is answered `Unavailable`, a further connection's channel on the same
/// circuit is closed at once, and another circuit's is served) and its own
/// streams (two: a third on the circuit is closed as it arrives); every
/// place, the streams' and the channels', is given back once its
/// connection ends.
#[cfg(feature = "tor")]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_onions_ssh_serves_the_screens_marked_onion_and_limited_per_circuit() {
    const GATED: InstanceId = InstanceId(1);
    let served = served();
    let target = Target::socket(served.socket.clone());
    let operator = Operator::signing(&target, SigningKey::from_bytes(&OPERATOR), served.node.id());
    let (gated, identity) = tokio::task::spawn_blocking(move || {
        let Ok(Response::Created(agent)) = operator.create_agent(Vec::new()) else {
            panic!("an agent")
        };
        let elf = vos_checker::programs::package("gated");
        vos_checker::calls::installed(
            operator
                .install(agent, &vos_checker::calls::install_of(GATED, &elf))
                .unwrap(),
        );
        let identity = Client::new(&target, SigningKey::from_bytes(&[1; 32]))
            .identity(agent)
            .unwrap();
        (agent, identity)
    })
    .await
    .unwrap();
    let query = |key: u8| {
        let query = signed_query(
            &identity,
            &SigningKey::from_bytes(&[key; 32]),
            served.clock.load(Ordering::SeqCst) + 10_000,
            Consistency::Applied { at: 0 },
            GATED,
            vos_abi::ids::MethodId(vos_abi::ids::derive_id("vos/method/", "count")),
            Vec::new(),
        );
        frame(
            Framing::Stream,
            Kind::Query as u16,
            1,
            &(gated, query).encode(),
        )
    };
    let (onion, _dir) = onion(served.node.id().0, &served.socket, 2, 2);
    let handle = over_circuit(&onion, 7).await.unwrap();
    // The screen, on a terminal.
    let mut shell = handle.channel_open_session().await.unwrap();
    shell
        .request_pty(true, "xterm-256color", 100, 30, 800, 480, &[])
        .await
        .unwrap();
    shell.request_shell(true).await.unwrap();
    let mut screen = Vec::new();
    let shown = tokio::time::timeout(Duration::from_secs(30), async {
        while !text(&screen).contains("vos-gateway") {
            match shell.wait().await {
                Some(ChannelMsg::Data { data }) => screen.extend_from_slice(&data),
                Some(ChannelMsg::Eof | ChannelMsg::Close) | None => return false,
                Some(_) => {}
            }
        }
        true
    })
    .await;
    assert_eq!(shown, Ok(true), "{:?}", text(&screen));
    // The subsystem beside it, marking onion.
    let mut channel = subsystem(&handle).await;
    let mut answers = Answers { buffer: Vec::new() };
    channel.data(&query(72)[..]).await.unwrap();
    let (kind, _, answer) = answers.next(&mut channel).await.unwrap();
    assert_eq!(kind, Kind::Query as u16);
    let answer = Response::decode_exact(&answer).unwrap();
    assert!(
        matches!(answer, Response::Ran { .. }),
        "the onion's mark reached the node: {answer:?}"
    );
    // A second channel takes the circuit's other place; its requests count
    // among the circuit's in flight, not its channels, and are served.
    let mut full = subsystem(&handle).await;
    full.data(&query(73)[..]).await.unwrap();
    let (kind, _, answer) = Answers { buffer: Vec::new() }
        .next(&mut full)
        .await
        .unwrap();
    assert_eq!(kind, Kind::Query as u16, "the circuit's second channel");
    assert!(matches!(
        Response::decode_exact(&answer),
        Some(Response::Ran { .. })
    ));
    // A further connection on the circuit is served no channel; another
    // circuit's is.
    let second = over_circuit(&onion, 7).await.unwrap();
    let mut refused = subsystem(&second).await;
    refused.data(&query(74)[..]).await.unwrap_or(());
    assert_eq!(
        Answers { buffer: Vec::new() }.next(&mut refused).await,
        None,
        "past the circuit's channels"
    );
    let other = over_circuit(&onion, 8).await.unwrap();
    let mut served_other = subsystem(&other).await;
    served_other.data(&query(75)[..]).await.unwrap();
    let (kind, _, answer) = Answers { buffer: Vec::new() }
        .next(&mut served_other)
        .await
        .unwrap();
    assert_eq!(kind, Kind::Query as u16, "another circuit's own channel");
    assert!(matches!(
        Response::decode_exact(&answer),
        Some(Response::Ran { .. })
    ));
    // Circuit 7 holds its two streams: a third is closed as it arrives.
    assert_eq!(onion.circuits.streams(7), 2);
    assert!(
        over_circuit(&onion, 7).await.is_err(),
        "past the circuit's streams"
    );
    // Every place given back once the connections end.
    drop((shell, channel, full, refused, served_other));
    drop((handle, second, other));
    for _ in 0..100 {
        if onion.circuits.streams(7) + onion.circuits.streams(8) == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert_eq!(onion.circuits.streams(7) + onion.circuits.streams(8), 0);
    // And the circuit's channel places, once their tasks end: a new
    // connection's channel and its request take both again.
    let mut given_back = false;
    for _ in 0..100 {
        let again = over_circuit(&onion, 7).await.unwrap();
        let mut channel = subsystem(&again).await;
        channel.data(&query(76)[..]).await.unwrap();
        let answer = Answers { buffer: Vec::new() }.next(&mut channel).await;
        if answer.map(|(kind, _, _)| kind) == Some(Kind::Query as u16) {
            given_back = true;
            break;
        }
        drop((channel, again));
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(given_back, "the circuit's places given back");
}
