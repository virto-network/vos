//! What the QUIC tests share.

#![allow(dead_code)]

use std::future::Future;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vos_net::quic::{Config, Quic};
use vos_net::{Arrivals, Class, Incoming, Network, NodeNumber, Peer, Refused, public_key};

/// Node `number`'s secret seed.
pub fn secret(number: NodeNumber) -> [u8; 32] {
    [number; 32]
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
pub fn config(number: NodeNumber) -> Config {
    Config::new(number, secret(number), any_port())
}

pub fn bind(number: NodeNumber) -> (Quic, Arrivals) {
    Quic::bind(config(number)).unwrap()
}

/// Bind `address` again once the last run has let it go.
pub async fn rebind(number: NodeNumber, address: SocketAddr) -> (Quic, Arrivals) {
    let started = Instant::now();
    loop {
        match Quic::bind(Config::new(number, secret(number), address)) {
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
pub fn peer_at(number: NodeNumber, address: SocketAddr) -> Peer {
    Peer {
        number,
        key: public_key(&secret(number)),
        address,
    }
}

pub fn peer_of(number: NodeNumber, quic: &Quic) -> Peer {
    Peer {
        number,
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
    let numbers: Vec<NodeNumber> = configs.iter().map(|config| config.number).collect();
    let nodes: Vec<_> = configs
        .into_iter()
        .map(|config| Quic::bind(config).unwrap())
        .collect();
    let peers: Vec<Peer> = nodes
        .iter()
        .zip(numbers)
        .map(|((quic, _), number)| peer_of(number, quic))
        .collect();
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
pub async fn send(
    network: &impl Network,
    to: NodeNumber,
    class: Class,
    stream: u64,
    frame: Vec<u8>,
) {
    loop {
        match network.send(to, class, stream, frame.clone()) {
            Ok(()) => return,
            Err(Refused::Full) => network.ready(to, class).await,
            Err(refused) => panic!("refused: {refused:?}"),
        }
    }
}

pub fn queue(arrivals: &Arrivals, class: Class) -> &smol::channel::Receiver<Incoming> {
    match class {
        Class::Liveness => &arrivals.liveness,
        Class::Consensus => &arrivals.consensus,
        Class::Requests => &arrivals.requests,
        Class::Bulk => &arrivals.bulk,
    }
}

/// Nothing arrives on any class within `limit`.
pub async fn silent(arrivals: &Arrivals, limit: Duration) -> bool {
    let any = async {
        arrivals
            .liveness
            .recv()
            .or(arrivals.consensus.recv())
            .or(arrivals.requests.recv())
            .or(arrivals.bulk.recv())
            .await
    };
    within(limit, any).await.is_none()
}
