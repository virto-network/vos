//! The `vos-api` subsystem on the gateway's SSH port, under an ephemeral
//! key: the relay set relayed and the node's time through it; any other
//! kind refused `NotRelayed`, the channel closed and no node asked; a node
//! gone answered `Unavailable` with the channel kept; at most 16 requests
//! in flight a channel.

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
    let gateway = Arc::new(Gateway::new(vec![Upstream::new(
        key,
        Address::Socket(socket),
        [41; 32],
    )]));
    let host_key = ssh_key::PrivateKey::from(ssh_key::private::Ed25519Keypair::from_seed(&[3; 32]));
    let server =
        vos_gateway::ssh::server(host_key, gateway, Limits::new(PerAddress::default()), None);
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
    let reply = tokio::time::timeout(Duration::from_secs(5), channel.wait())
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
            if self.buffer.len() >= 14 {
                let length = u32::from_le_bytes(self.buffer[..4].try_into().unwrap()) as usize;
                if self.buffer.len() >= 4 + length {
                    let kind = u16::from_le_bytes(self.buffer[4..6].try_into().unwrap());
                    let id = u64::from_le_bytes(self.buffer[6..14].try_into().unwrap());
                    let body = self.buffer[14..4 + length].to_vec();
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
    // A call's header alone: refused before its body, no node asked.
    let header = vos_api::Header::of(Framing::Stream, Kind::Call as u16, 3, 100);
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
