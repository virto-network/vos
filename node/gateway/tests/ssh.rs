//! The `vos-api` subsystem on the gateway's SSH port, under an ephemeral
//! key: the relay set relayed and the node's time through it, a session's
//! calls among them; any other kind refused `NotRelayed`, the channel
//! closed and no node asked; a node gone answered `Unavailable` with the
//! channel kept; at most 16 requests in flight a channel; each frame
//! marked with its port's transport; and a flood of junk proven calls
//! held to the port's caps, answered `Busy` past them, while a member's
//! calls are served.

#![cfg(feature = "ssh")]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use russh::keys::ssh_key;
use russh::{ChannelMsg, client};
use vos_api::{FRAME_ERROR, FrameError, Framing, Kind, frame};
use vos_checker::programs::Programs;
use vos_gateway::Gateway;
use vos_gateway::limits::{Limits, PerAddress};
use vos_gateway::upstream::{Address, Upstream};
use vos_node::client::{Client, Operator, Target, signed_query};
use vos_node::{Config, Node};
use vos_wire::ids::InstanceId;
use vos_wire::ingress::{Consistency, Rejection, Response};
use vos_wire::{Decode, Encode};

const OPERATOR: [u8; 32] = [31; 32];
const COUNTER: InstanceId = InstanceId(1);

struct AcceptAll;

impl client::Handler for AcceptAll {
    type Error = russh::Error;

    async fn check_server_key(&mut self, _key: &ssh_key::PublicKey) -> Result<bool, Self::Error> {
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
    let mut config = Config::new(programs.agent.clone());
    config.executors = 2;
    config.clock = {
        let clock = Arc::clone(&clock);
        Arc::new(move || clock.load(Ordering::SeqCst))
    };
    config.operators = vec![SigningKey::from_bytes(&OPERATOR).verifying_key().to_bytes()];
    let node = Node::open(dir.path(), config).unwrap();
    let socket = dir.path().join("api.sock");
    node.serve_socket(&socket, 0o600).unwrap();
    Served {
        node,
        socket,
        clock,
        _dir: dir,
    }
}

/// An SSH port relaying to the node at `socket`, and its address.
async fn port(key: [u8; 32], socket: PathBuf) -> std::net::SocketAddr {
    port_marked(key, socket, vos_api::Mark::Clearnet).await
}

/// An SSH port relaying to the node at `socket`, marking each frame
/// `mark`, and its address.
async fn port_marked(key: [u8; 32], socket: PathBuf, mark: vos_api::Mark) -> std::net::SocketAddr {
    let gateway = Arc::new(Gateway::new(vec![Upstream::new(
        key,
        Address::Socket(socket),
        [41; 32],
    )]));
    let host_key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[3; 32]));
    let port = vos_gateway::ssh::Port::tcp(
        mark,
        Limits::new(PerAddress::default()),
        vos_gateway::caps::Caps::none(),
        vos_gateway::caps::bodies(),
    );
    let server = vos_gateway::ssh::server(host_key, gateway, port, None);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.serve_on(listener).await;
    });
    address
}

/// The subsystem's channel, under an ephemeral key.
async fn channel(address: std::net::SocketAddr) -> russh::Channel<client::Msg> {
    let mut seed = [0u8; 32];
    seed[..8].copy_from_slice(&vos_node::wall_clock().to_le_bytes());
    let key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&seed));
    let mut handle = client::connect(Arc::new(client::Config::default()), address, AcceptAll)
        .await
        .unwrap();
    let key = russh::keys::PrivateKeyWithHashAlg::new(Arc::new(key), None);
    assert!(
        handle
            .authenticate_publickey("anyone", key)
            .await
            .unwrap()
            .success()
    );
    let mut channel = handle.channel_open_session().await.unwrap();
    channel
        .request_subsystem(true, vos_gateway::ssh::SUBSYSTEM)
        .await
        .unwrap();
    // A bound on the wait, which a loaded host may stretch.
    let reply = tokio::time::timeout(Duration::from_secs(30), channel.wait())
        .await
        .unwrap();
    assert!(matches!(reply, Some(ChannelMsg::Success)), "{reply:?}");
    // The connection lives as long as its channel's test.
    std::mem::forget(handle);
    channel
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
    let asked = served.node.api_frames();
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
    assert_eq!(served.node.api_frames(), asked);
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
    let served = served();
    let target = Target::socket(served.socket.clone());
    let operator = Operator::signing(&target, SigningKey::from_bytes(&OPERATOR), served.node.id());
    let (agent, identity, value) = tokio::task::spawn_blocking(move || {
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
    .unwrap();
    let address = port(served.node.id().0, served.socket.clone()).await;
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
        vos_wire::ids::MethodId(vos_wire::ids::derive_id("vos/method/", "count")),
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
    let target = Target::socket(served.socket.clone());
    let operator = Operator::signing(&target, SigningKey::from_bytes(&OPERATOR), served.node.id());
    let (agent, identity, value) = tokio::task::spawn_blocking(move || {
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
    .unwrap();
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
        agent_rate: 1_000,
        agent_burst: 1_000,
    });
    let gateway = Arc::new(Gateway::new(vec![Upstream::new(
        served.node.id().0,
        Address::Socket(standing.socket.clone()),
        [41; 32],
    )]));
    let host_key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[3; 32]));
    let port = vos_gateway::ssh::Port::tcp(
        vos_api::Mark::Onion,
        Limits::new(PerAddress::default()),
        Arc::clone(&caps),
        vos_gateway::caps::bodies(),
    );
    let server = vos_gateway::ssh::server(host_key, gateway, port, None);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = server.serve_on(listener).await;
    });
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
        agent_rate: 1_000,
        agent_burst: 1_000,
    });
    let roomy_address = {
        let gateway = Arc::new(Gateway::new(vec![Upstream::new(
            served.node.id().0,
            Address::Socket(slow.socket.clone()),
            [41; 32],
        )]));
        let host_key =
            ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[4; 32]));
        let port = vos_gateway::ssh::Port::tcp(
            vos_api::Mark::Onion,
            Limits::new(PerAddress::default()),
            Arc::clone(&roomy),
            vos_gateway::caps::bodies(),
        );
        let server = vos_gateway::ssh::server(host_key, gateway, port, None);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = server.serve_on(listener).await;
        });
        address
    };
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
    let session = vos_wire::ids::Session {
        key: key.verifying_key().to_bytes(),
        name: [3; 16],
        t0: served.clock.load(Ordering::SeqCst),
    };
    let increment = vos_wire::ids::MethodId(vos_wire::ids::derive_id("vos/method/", "increment"));
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
