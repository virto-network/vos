//! Endpoints joined through an in-process hub.

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use common::{ALL, CONSENSUS, LIVENESS, MAX_FRAME, classes, with_frames, within};
use vnet::memory::{Endpoint, Hub};
use vnet::{Arrivals, Class, Incoming, Network, NodeKey, Peer, Refused};

/// Node `number`'s key: the hub checks no key.
fn k(number: u8) -> NodeKey {
    [number; 32]
}

fn hub(seed: u64) -> Hub {
    Hub::new(seed, classes())
}

fn peers(numbers: &[u8]) -> Vec<Peer> {
    let unused: SocketAddr = "0.0.0.0:0".parse().unwrap();
    numbers
        .iter()
        .map(|number| Peer {
            key: k(*number),
            address: unused,
        })
        .collect()
}

fn join(hub: &Hub, numbers: &[u8]) -> Vec<(Endpoint, Arrivals)> {
    numbers
        .iter()
        .map(|number| {
            let (endpoint, arrivals) = hub.join(k(*number));
            endpoint.set_peers(peers(numbers));
            (endpoint, arrivals)
        })
        .collect()
}

/// Send `frame` to node `to` on Consensus stream 0, which takes it.
fn send(from: &Endpoint, to: u8, frame: &[u8]) {
    from.send(k(to), CONSENSUS, 0, frame.to_vec()).unwrap();
}

fn drain(queue: &smol::channel::Receiver<Incoming>) -> Vec<Vec<u8>> {
    std::iter::from_fn(|| queue.try_recv().ok())
        .map(|incoming| incoming.frame)
        .collect()
}

#[test]
fn frames_arrive_with_their_sender_and_stream() {
    let hub = hub(1);
    let nodes = join(&hub, &[1, 2, 3]);
    for class in ALL {
        nodes[0].0.send(k(2), class, 5, vec![class.0]).unwrap();
    }
    for class in ALL {
        let incoming = nodes[1].1.queue(class).try_recv().unwrap();
        assert_eq!(
            (incoming.from, incoming.stream, incoming.frame),
            (k(1), 5, vec![class.0])
        );
    }
    assert!(nodes[2].1.queue(CONSENSUS).try_recv().is_err());
}

#[test]
fn sends_are_refused_with_a_reason() {
    let hub = hub(1);
    let mut small = MAX_FRAME;
    small[usize::from(CONSENSUS)] = 16;
    hub.set_classes(with_frames(small));
    let nodes = join(&hub, &[1, 2]);
    let (a, _) = &nodes[0];
    assert_eq!(
        a.send(k(9), CONSENSUS, 0, Vec::new()),
        Err(Refused::UnknownPeer)
    );
    assert_eq!(
        a.send(k(2), CONSENSUS, 0, vec![0; 17]),
        Err(Refused::TooLarge)
    );
    assert_eq!(
        a.send(k(2), Class(ALL.len() as u8), 0, Vec::new()),
        Err(Refused::UnknownClass)
    );
    let mut sent = 0;
    let full = loop {
        match a.send(k(2), CONSENSUS, 0, Vec::new()) {
            Ok(()) => sent += 1,
            Err(refused) => break refused,
        }
    };
    assert_eq!(full, Refused::Full);
    assert!(sent > 0);
    // Ready once the receiver takes one.
    smol::block_on(async {
        assert!(
            within(Duration::from_millis(20), a.ready(k(2), CONSENSUS))
                .await
                .is_none()
        );
        nodes[1].1.queue(CONSENSUS).try_recv().unwrap();
        // A bound on the wait, which a loaded host may stretch.
        assert!(
            within(Duration::from_secs(30), a.ready(k(2), CONSENSUS))
                .await
                .is_some()
        );
    });
}

#[test]
fn a_partition_loses_frames_until_healed() {
    let hub = hub(1);
    let nodes = join(&hub, &[1, 2, 3]);
    hub.partition(k(1), k(2));
    send(&nodes[0].0, 2, b"lost");
    send(&nodes[1].0, 1, b"lost");
    send(&nodes[0].0, 3, b"kept");
    assert!(drain(nodes[1].1.queue(CONSENSUS)).is_empty());
    assert!(drain(nodes[0].1.queue(CONSENSUS)).is_empty());
    assert_eq!(drain(nodes[2].1.queue(CONSENSUS)), vec![b"kept".to_vec()]);
    hub.isolate(k(2));
    send(&nodes[2].0, 2, b"lost");
    assert!(drain(nodes[1].1.queue(CONSENSUS)).is_empty());
    hub.heal();
    send(&nodes[0].0, 2, b"healed");
    assert_eq!(drain(nodes[1].1.queue(CONSENSUS)), vec![b"healed".to_vec()]);
}

#[test]
fn losses_follow_the_rate() {
    let hub = hub(42);
    let nodes = join(&hub, &[1, 2]);
    hub.set_loss(250_000);
    let mut arrived = 0;
    for i in 0..4000u32 {
        nodes[0]
            .0
            .send(k(2), LIVENESS, 0, i.to_be_bytes().to_vec())
            .unwrap();
        arrived += drain(nodes[1].1.queue(LIVENESS)).len();
    }
    assert!((2800..3200).contains(&arrived), "{arrived} of 4000 arrived");
}

#[test]
fn delayed_frames_arrive_late_and_in_order() {
    let hub = hub(1);
    let nodes = join(&hub, &[1, 2]);
    hub.set_delay(Duration::from_millis(30));
    let started = Instant::now();
    for i in 0..100u32 {
        send(&nodes[0].0, 2, &i.to_be_bytes());
    }
    // Back to no delay: later frames still queue behind the delayed ones.
    hub.set_delay(Duration::ZERO);
    send(&nodes[0].0, 2, &100u32.to_be_bytes());
    smol::block_on(async {
        // A bound on each wait, which a loaded host may stretch.
        for i in 0..=100u32 {
            let incoming = within(Duration::from_secs(30), nodes[1].1.queue(CONSENSUS).recv())
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
    let hub = hub(1);
    let mut nodes = join(&hub, &[1, 2]);
    let (old, _) = nodes.pop().unwrap();
    // Down: what is sent to it is lost.
    drop(old);
    send(&nodes[0].0, 2, b"lost");
    let (restarted, arrivals) = hub.join(k(2));
    restarted.set_peers(peers(&[1, 2]));
    send(&nodes[0].0, 2, b"back");
    assert_eq!(drain(arrivals.queue(CONSENSUS)), vec![b"back".to_vec()]);
    // An old endpoint dropped after its replacement joined leaves it be.
    let (stale, _) = hub.join(k(3));
    let (replacement, replacement_arrivals) = hub.join(k(3));
    replacement.set_peers(peers(&[1, 3]));
    drop(stale);
    nodes[0].0.set_peers(peers(&[1, 2, 3]));
    send(&nodes[0].0, 3, b"kept");
    assert_eq!(
        drain(replacement_arrivals.queue(CONSENSUS)),
        vec![b"kept".to_vec()]
    );
    drop(replacement);
}

#[test]
fn a_node_takes_frames_only_from_the_peers_it_lists() {
    let hub = hub(1);
    let nodes = join(&hub, &[1, 2]);
    let (stranger, _) = hub.join(k(9));
    stranger.set_peers(peers(&[2, 9]));
    send(&stranger, 2, b"unlisted");
    assert!(drain(nodes[1].1.queue(CONSENSUS)).is_empty());
    nodes[1].0.set_peers(peers(&[1, 2, 9]));
    send(&stranger, 2, b"listed");
    assert_eq!(drain(nodes[1].1.queue(CONSENSUS)), vec![b"listed".to_vec()]);
}

#[test]
fn a_node_whose_consumer_is_gone_loses_frames_without_a_wait() {
    let hub = hub(1);
    let mut nodes = join(&hub, &[1, 2]);
    let (_endpoint, arrivals) = nodes.pop().unwrap();
    drop(arrivals);
    let (a, _) = &nodes[0];
    for _ in 0..2000 {
        assert_eq!(a.send(k(2), CONSENSUS, 0, Vec::new()), Ok(()));
    }
    smol::block_on(async {
        assert!(
            within(Duration::from_secs(1), a.ready(k(2), CONSENSUS))
                .await
                .is_some()
        );
    });
}

#[test]
fn a_delayed_link_is_not_held_up_by_a_full_old_run() {
    let hub = hub(1);
    let mut nodes = join(&hub, &[1, 2]);
    hub.set_delay(Duration::from_millis(1));
    // The old run's queue fills, and is kept, unread.
    let (old, old_arrivals) = nodes.pop().unwrap();
    for i in 0..1100u32 {
        send(&nodes[0].0, 2, &i.to_be_bytes());
    }
    smol::block_on(async {
        while !old_arrivals.queue(CONSENSUS).is_full() {
            smol::Timer::after(Duration::from_millis(1)).await;
        }
    });
    let (restarted, arrivals) = hub.join(k(2));
    restarted.set_peers(peers(&[1, 2]));
    send(&nodes[0].0, 2, b"after");
    smol::block_on(async {
        loop {
            let incoming = within(Duration::from_secs(1), arrivals.queue(CONSENSUS).recv())
                .await
                .expect("the restarted run is reached")
                .unwrap();
            if incoming.frame == b"after" {
                break;
            }
        }
    });
    drop((old, old_arrivals));
}
