//! What the QUIC tests share.

#![allow(dead_code)]

use std::future::Future;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vos_net::quic::{Config, Quic};
use vos_net::{Arrivals, Class, Incoming, Limits, Network, NodeNumber, Peer, Refused};

/// Node `number`'s secret seed.
pub fn secret(number: NodeNumber) -> [u8; 32] {
    [number; 32]
}

pub fn any_port() -> SocketAddr {
    "127.0.0.1:0".parse().unwrap()
}

pub fn bind(number: NodeNumber, listen: SocketAddr, limits: Limits) -> (Quic, Arrivals) {
    Quic::bind(Config {
        limits,
        ..Config::new(number, secret(number), listen)
    })
    .unwrap()
}

/// Bind `address` again once the last run has let it go.
pub async fn rebind(number: NodeNumber, address: SocketAddr) -> (Quic, Arrivals) {
    let started = Instant::now();
    loop {
        match Quic::bind(Config::new(number, secret(number), address)) {
            Ok(bound) => return bound,
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                assert!(
                    started.elapsed() < Duration::from_secs(2),
                    "{address} stays in use"
                );
                smol::Timer::after(Duration::from_millis(5)).await;
            }
            Err(error) => panic!("{error}"),
        }
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
    let nodes: Vec<_> = (1..=count)
        .map(|number| bind(number, any_port(), Limits::default()))
        .collect();
    let peers: Vec<Peer> = nodes
        .iter()
        .zip(1..)
        .map(|((quic, _), number)| peer_of(number, quic))
        .collect();
    for (quic, _) in &nodes {
        quic.set_peers(peers.clone());
    }
    nodes
}

pub async fn within<T>(limit: Duration, future: impl Future<Output = T>) -> Option<T> {
    async { Some(future.await) }
        .or(async {
            smol::Timer::after(limit).await;
            None
        })
        .await
}

pub async fn next(queue: &smol::channel::Receiver<Incoming>) -> Incoming {
    within(Duration::from_secs(10), queue.recv())
        .await
        .expect("a frame within 10 s")
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
