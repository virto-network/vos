//! What the QUIC tests share.

#![allow(dead_code)]

use std::future::Future;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vnet::quic::{Config, Protocol, Quic};
use vnet::{
    Arrivals, Class, ClassSpec, Classes, Incoming, Network, NodeKey, Peer, Refused, Streams,
    public_key,
};

/// The tests' four classes: pair heartbeats, sent first and dropped once
/// stale; two classes of streams per id; and large frames, a stream each.
pub const LIVENESS: Class = 0;
pub const CONSENSUS: Class = 1;
pub const REQUESTS: Class = 2;
pub const BULK: Class = 3;
pub const ALL: [Class; 4] = [LIVENESS, CONSENSUS, REQUESTS, BULK];

/// How long a liveness frame may wait to be sent: long, so no test that
/// expects one to arrive depends on a loaded host's pace.
pub const LIVENESS_AGE: Duration = Duration::from_secs(1);

/// The definitions of [`ALL`], with `max_frame` bounds.
pub fn specs(max_frame: [usize; 4]) -> [ClassSpec; 4] {
    let class = |priority, max_frame, arrivals, streams| ClassSpec {
        priority,
        max_frame,
        arrivals,
        streams,
        max_age: None,
    };
    [
        ClassSpec {
            max_age: Some(LIVENESS_AGE),
            ..class(3, max_frame[0], 1024, Streams::PerId)
        },
        class(2, max_frame[1], 1024, Streams::PerId),
        class(1, max_frame[2], 1024, Streams::PerId),
        class(0, max_frame[3], 16, Streams::PerFrame),
    ]
}

/// The largest frame of each of [`ALL`].
pub const MAX_FRAME: [usize; 4] = [64 << 10, 5 << 20, 1 << 20, (64 << 20) + (64 << 10)];

/// [`ALL`] with the bounds of [`MAX_FRAME`].
pub fn classes() -> Classes {
    with_frames(MAX_FRAME)
}

/// [`ALL`] with the frame bounds `max_frame`.
pub fn with_frames(max_frame: [usize; 4]) -> Classes {
    Classes::new(specs(max_frame)).unwrap()
}

/// The peers' protocol.
pub const ALPN: &[u8] = b"test/1";

pub fn protocol() -> Protocol {
    Protocol {
        alpn: ALPN.to_vec(),
        domain: b"test/".to_vec(),
    }
}

/// Node `number`'s secret seed.
pub fn secret(number: u8) -> [u8; 32] {
    [number; 32]
}

/// Node `number`'s key.
pub fn key(number: u8) -> NodeKey {
    public_key(&secret(number))
}

pub fn any_port() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

/// An address nothing listens on: a port the system gave, let go again.
pub fn vacant_address() -> SocketAddr {
    std::net::UdpSocket::bind(any_port())
        .unwrap()
        .local_addr()
        .unwrap()
}

/// Node `number`'s configuration, on any port.
pub fn config(number: u8) -> Config {
    Config::new(secret(number), any_port(), protocol(), classes())
}

pub fn bind(number: u8) -> (Quic, Arrivals) {
    Quic::bind(config(number)).unwrap()
}

/// Bind `address` again once the last run has let it go.
pub async fn rebind(number: u8, address: SocketAddr) -> (Quic, Arrivals) {
    let started = Instant::now();
    loop {
        match Quic::bind(Config::new(secret(number), address, protocol(), classes())) {
            Ok(bound) => return bound,
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                // A bound on the wait, not what is tested: a loaded host
                // may take seconds to let the address go.
                assert!(
                    started.elapsed() < Duration::from_secs(30),
                    "{address} stays in use"
                );
                smol::Timer::after(Duration::from_millis(5)).await;
            }
            Err(error) => panic!("{error}"),
        }
    }
}

/// Node `number`, by the key its secret gives, at `address`.
pub fn peer_at(number: u8, address: SocketAddr) -> Peer {
    Peer {
        key: key(number),
        address,
    }
}

pub fn peer_of(quic: &Quic) -> Peer {
    Peer {
        key: quic.key(),
        address: quic.local_addr(),
    }
}

/// Nodes 1..=count, each configured with every other.
pub fn cluster(count: u8) -> Vec<(Quic, Arrivals)> {
    join((1..=count).map(config).collect())
}

/// Nodes `a` and `b`, each configured with the other.
pub fn pair(a: Config, b: Config) -> ((Quic, Arrivals), (Quic, Arrivals)) {
    let mut nodes = join(vec![a, b]);
    let b = nodes.pop().unwrap();
    (nodes.pop().unwrap(), b)
}

/// A node of each configuration, each configured with every other.
fn join(configs: Vec<Config>) -> Vec<(Quic, Arrivals)> {
    let nodes: Vec<_> = configs
        .into_iter()
        .map(|config| Quic::bind(config).unwrap())
        .collect();
    let peers: Vec<Peer> = nodes.iter().map(|(quic, _)| peer_of(quic)).collect();
    for (quic, _) in &nodes {
        quic.set_peers(peers.clone());
    }
    nodes
}

/// Node 1, configured with node 2 at an address nothing listens on yet.
pub fn node_1() -> (Quic, Arrivals, SocketAddr) {
    let (a, arrivals) = bind(1);
    let address = vacant_address();
    a.set_peers(vec![peer_at(2, address)]);
    (a, arrivals, address)
}

/// The `percent`th percentile of `sorted`.
pub fn percentile(sorted: &[Duration], percent: usize) -> Duration {
    sorted[(sorted.len() * percent / 100).min(sorted.len() - 1)]
}

pub async fn within<T>(limit: Duration, future: impl Future<Output = T>) -> Option<T> {
    async { Some(future.await) }
        .or(async {
            smol::Timer::after(limit).await;
            None
        })
        .await
}

/// The next frame `queue` takes: within 30 s, a bound on the wait, which a
/// loaded host may stretch, not what a test checks.
pub async fn next(queue: &smol::channel::Receiver<Incoming>) -> Incoming {
    within(Duration::from_secs(30), queue.recv())
        .await
        .expect("a frame within 30 s")
        .unwrap()
}

/// Send, waiting while the queue is full.
pub async fn send(network: &impl Network, to: NodeKey, class: Class, stream: u64, frame: Vec<u8>) {
    loop {
        match network.send(to, class, stream, frame.clone()) {
            Ok(()) => return,
            Err(Refused::Full) => network.ready(to, class).await,
            Err(refused) => panic!("refused: {refused:?}"),
        }
    }
}

/// Nothing arrives on any class within `limit`.
pub async fn silent(arrivals: &Arrivals, limit: Duration) -> bool {
    let any = async {
        arrivals
            .queue(LIVENESS)
            .recv()
            .or(arrivals.queue(CONSENSUS).recv())
            .or(arrivals.queue(REQUESTS).recv())
            .or(arrivals.queue(BULK).recv())
            .await
    };
    within(limit, any).await.is_none()
}
