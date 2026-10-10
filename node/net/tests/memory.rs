//! Endpoints joined through an in-process hub.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vos_net::memory::{Endpoint, Hub};
use vos_net::{Arrivals, Class, Incoming, Limits, Network, NodeNumber, Peer, Refused};

fn peers(numbers: &[NodeNumber]) -> Vec<Peer> {
    let unused: SocketAddr = "0.0.0.0:0".parse().unwrap();
    numbers
        .iter()
        .map(|number| Peer {
            number: *number,
            key: [*number; 32],
            address: unused,
        })
        .collect()
}

fn join(hub: &Hub, numbers: &[NodeNumber]) -> Vec<(Endpoint, Arrivals)> {
    numbers
        .iter()
        .map(|number| {
            let (endpoint, arrivals) = hub.join(*number);
            endpoint.set_peers(peers(numbers));
            (endpoint, arrivals)
        })
        .collect()
}

async fn within<T>(limit: Duration, future: impl Future<Output = T>) -> Option<T> {
    async { Some(future.await) }
        .or(async {
            smol::Timer::after(limit).await;
            None
        })
        .await
}

fn drain(queue: &smol::channel::Receiver<Incoming>) -> Vec<Vec<u8>> {
    std::iter::from_fn(|| queue.try_recv().ok())
        .map(|incoming| incoming.frame)
        .collect()
}

#[test]
fn frames_arrive_with_their_sender_and_stream() {
    let hub = Hub::default();
    let nodes = join(&hub, &[1, 2, 3]);
    for class in Class::ALL {
        nodes[0].0.send(2, class, 5, vec![class as u8]).unwrap();
    }
    for class in Class::ALL {
        let queue = match class {
            Class::Liveness => &nodes[1].1.liveness,
            Class::Consensus => &nodes[1].1.consensus,
            Class::Requests => &nodes[1].1.requests,
            Class::Bulk => &nodes[1].1.bulk,
        };
        let incoming = queue.try_recv().unwrap();
        assert_eq!(
            incoming,
            Incoming {
                from: 1,
                stream: 5,
                frame: vec![class as u8]
            }
        );
    }
    assert!(nodes[2].1.consensus.try_recv().is_err());
    let refused = nodes[0].0.send_to_all(Class::Liveness, 0, b"all");
    assert!(refused.is_empty());
    assert_eq!(drain(&nodes[1].1.liveness), vec![b"all".to_vec()]);
    assert_eq!(drain(&nodes[2].1.liveness), vec![b"all".to_vec()]);
}

#[test]
fn sends_are_refused_with_a_reason() {
    let hub = Hub::default();
    hub.set_limits(Limits {
        consensus: 16,
        ..Limits::default()
    });
    let nodes = join(&hub, &[1, 2]);
    let (a, _) = &nodes[0];
    assert_eq!(
        a.send(9, Class::Consensus, 0, Vec::new()),
        Err(Refused::UnknownPeer)
    );
    assert_eq!(
        a.send(2, Class::Consensus, 0, vec![0; 17]),
        Err(Refused::TooLarge)
    );
    let mut sent = 0;
    let full = loop {
        match a.send(2, Class::Consensus, 0, Vec::new()) {
            Ok(()) => sent += 1,
            Err(refused) => break refused,
        }
    };
    assert_eq!(full, Refused::Full);
    assert!(sent > 0);
    // Ready once the receiver takes one.
    smol::block_on(async {
        assert!(
            within(Duration::from_millis(20), a.ready(2, Class::Consensus))
                .await
                .is_none()
        );
        nodes[1].1.consensus.try_recv().unwrap();
        assert!(
            within(Duration::from_secs(1), a.ready(2, Class::Consensus))
                .await
                .is_some()
        );
    });
    a.close();
    assert_eq!(
        a.send(2, Class::Liveness, 0, Vec::new()),
        Err(Refused::Closed)
    );
}

#[test]
fn a_partition_loses_frames_until_healed() {
    let hub = Hub::default();
    let nodes = join(&hub, &[1, 2, 3]);
    hub.partition(1, 2);
    nodes[0]
        .0
        .send(2, Class::Consensus, 0, b"lost".to_vec())
        .unwrap();
    nodes[1]
        .0
        .send(1, Class::Consensus, 0, b"lost".to_vec())
        .unwrap();
    nodes[0]
        .0
        .send(3, Class::Consensus, 0, b"kept".to_vec())
        .unwrap();
    assert!(drain(&nodes[1].1.consensus).is_empty());
    assert!(drain(&nodes[0].1.consensus).is_empty());
    assert_eq!(drain(&nodes[2].1.consensus), vec![b"kept".to_vec()]);
    hub.cut(3, 1);
    nodes[2]
        .0
        .send(1, Class::Consensus, 0, b"lost".to_vec())
        .unwrap();
    nodes[0]
        .0
        .send(3, Class::Consensus, 0, b"one way".to_vec())
        .unwrap();
    assert!(drain(&nodes[0].1.consensus).is_empty());
    assert_eq!(drain(&nodes[2].1.consensus), vec![b"one way".to_vec()]);
    hub.isolate(2);
    nodes[2]
        .0
        .send(2, Class::Consensus, 0, b"lost".to_vec())
        .unwrap();
    assert!(drain(&nodes[1].1.consensus).is_empty());
    hub.heal();
    nodes[0]
        .0
        .send(2, Class::Consensus, 0, b"healed".to_vec())
        .unwrap();
    assert_eq!(drain(&nodes[1].1.consensus), vec![b"healed".to_vec()]);
}

#[test]
fn losses_follow_the_rate() {
    let hub = Hub::new(42);
    let nodes = join(&hub, &[1, 2]);
    hub.set_loss(250_000);
    let mut arrived = 0;
    for i in 0..4000u32 {
        nodes[0]
            .0
            .send(2, Class::Liveness, 0, i.to_be_bytes().to_vec())
            .unwrap();
        arrived += drain(&nodes[1].1.liveness).len();
    }
    assert!((2800..3200).contains(&arrived), "{arrived} of 4000 arrived");
}

#[test]
fn delayed_frames_arrive_late_and_in_order() {
    let hub = Hub::default();
    let nodes = join(&hub, &[1, 2]);
    hub.set_delay(Duration::from_millis(30));
    let started = Instant::now();
    for i in 0..100u32 {
        nodes[0]
            .0
            .send(2, Class::Consensus, 0, i.to_be_bytes().to_vec())
            .unwrap();
    }
    // Back to no delay: later frames still queue behind the delayed ones.
    hub.set_delay(Duration::ZERO);
    nodes[0]
        .0
        .send(2, Class::Consensus, 0, 100u32.to_be_bytes().to_vec())
        .unwrap();
    smol::block_on(async {
        for i in 0..=100u32 {
            let incoming = within(Duration::from_secs(1), nodes[1].1.consensus.recv())
                .await
                .unwrap()
                .unwrap();
            assert_eq!(incoming.frame, i.to_be_bytes().to_vec());
        }
    });
    assert!(started.elapsed() >= Duration::from_millis(30));
}

#[test]
fn a_restarted_node_takes_its_place() {
    let hub = Hub::default();
    let mut nodes = join(&hub, &[1, 2]);
    let (old, _) = nodes.pop().unwrap();
    // Down: what is sent to it is lost.
    drop(old);
    nodes[0]
        .0
        .send(2, Class::Consensus, 0, b"lost".to_vec())
        .unwrap();
    let (restarted, arrivals) = hub.join(2);
    restarted.set_peers(peers(&[1, 2]));
    nodes[0]
        .0
        .send(2, Class::Consensus, 0, b"back".to_vec())
        .unwrap();
    assert_eq!(drain(&arrivals.consensus), vec![b"back".to_vec()]);
    // An old endpoint dropped after its replacement joined leaves it be.
    let (stale, _) = hub.join(3);
    let (replacement, replacement_arrivals) = hub.join(3);
    replacement.set_peers(peers(&[1, 3]));
    drop(stale);
    nodes[0].0.set_peers(peers(&[1, 2, 3]));
    nodes[0]
        .0
        .send(3, Class::Consensus, 0, b"kept".to_vec())
        .unwrap();
    assert_eq!(
        drain(&replacement_arrivals.consensus),
        vec![b"kept".to_vec()]
    );
    drop(replacement);
}

#[test]
fn a_delayed_link_reaches_the_restarted_run() {
    let hub = Hub::default();
    let mut nodes = join(&hub, &[1, 2]);
    hub.set_delay(Duration::from_millis(5));
    nodes[0]
        .0
        .send(2, Class::Consensus, 0, b"first run".to_vec())
        .unwrap();
    let (old, old_arrivals) = nodes.pop().unwrap();
    smol::block_on(async {
        let first = within(Duration::from_secs(1), old_arrivals.consensus.recv()).await;
        assert_eq!(first.unwrap().unwrap().frame, b"first run");
    });
    drop((old, old_arrivals));
    let (restarted, arrivals) = hub.join(2);
    restarted.set_peers(peers(&[1, 2]));
    nodes[0]
        .0
        .send(2, Class::Consensus, 0, b"second run".to_vec())
        .unwrap();
    smol::block_on(async {
        let second = within(Duration::from_secs(1), arrivals.consensus.recv()).await;
        assert_eq!(
            second.expect("the restarted run reached").unwrap().frame,
            b"second run"
        );
    });
}

#[test]
fn a_node_takes_frames_only_from_the_peers_it_lists() {
    let hub = Hub::default();
    let nodes = join(&hub, &[1, 2]);
    let (stranger, _) = hub.join(9);
    stranger.set_peers(peers(&[2, 9]));
    stranger
        .send(2, Class::Consensus, 0, b"unlisted".to_vec())
        .unwrap();
    assert!(drain(&nodes[1].1.consensus).is_empty());
    nodes[1].0.set_peers(peers(&[1, 2, 9]));
    stranger
        .send(2, Class::Consensus, 0, b"listed".to_vec())
        .unwrap();
    assert_eq!(drain(&nodes[1].1.consensus), vec![b"listed".to_vec()]);
}

#[test]
fn a_node_whose_consumer_is_gone_loses_frames_without_a_wait() {
    let hub = Hub::default();
    let mut nodes = join(&hub, &[1, 2]);
    let (_endpoint, arrivals) = nodes.pop().unwrap();
    drop(arrivals);
    let (a, _) = &nodes[0];
    for _ in 0..2000 {
        assert_eq!(a.send(2, Class::Consensus, 0, Vec::new()), Ok(()));
    }
    smol::block_on(async {
        assert!(
            within(Duration::from_secs(1), a.ready(2, Class::Consensus))
                .await
                .is_some()
        );
    });
}
