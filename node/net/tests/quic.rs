//! Nodes on localhost over QUIC.

mod common;

use std::time::{Duration, Instant};

use common::*;
use vos_net::quic::{Config, Quic};
use vos_net::{Class, Limits, Network, NodeNumber, Peer, Refused, public_key};

#[test]
fn three_nodes_exchange_frames_on_every_class() {
    smol::block_on(async {
        let nodes = cluster(3);
        let others = |number: NodeNumber| (1..=3).filter(move |other| *other != number);
        // A liveness frame never waits for a connection: connect first.
        for ((quic, _), number) in nodes.iter().zip(1..) {
            for to in others(number) {
                send(quic, to, Class::Consensus, 0, b"hello".to_vec()).await;
            }
        }
        for (_, arrivals) in &nodes {
            for _ in 0..2 {
                assert_eq!(next(&arrivals.consensus).await.frame, b"hello");
            }
        }
        for ((quic, _), number) in nodes.iter().zip(1..) {
            for to in others(number) {
                for class in Class::ALL {
                    let frame = format!("{class:?} to {to}").into_bytes();
                    send(quic, to, class, u64::from(to) * 10, frame).await;
                }
            }
        }
        for ((_, arrivals), number) in nodes.iter().zip(1u8..) {
            for class in Class::ALL {
                let mut from: Vec<NodeNumber> = Vec::new();
                for _ in 0..2 {
                    let incoming = next(queue(arrivals, class)).await;
                    assert_eq!(
                        incoming.frame,
                        format!("{class:?} to {number}").into_bytes()
                    );
                    assert_eq!(incoming.stream, u64::from(number) * 10);
                    from.push(incoming.from);
                }
                from.sort();
                let others: Vec<_> = others(number).collect();
                assert_eq!(from, others, "node {number}, {class:?}");
            }
        }
    });
}

#[test]
fn frames_keep_their_order_within_a_stream() {
    smol::block_on(async {
        let nodes = cluster(2);
        let (a, _) = &nodes[0];
        let (_, b) = &nodes[1];
        const FRAMES: u32 = 2000;
        for i in 0..FRAMES {
            send(a, 2, Class::Consensus, 7, i.to_be_bytes().to_vec()).await;
            send(a, 2, Class::Requests, 8, i.to_be_bytes().to_vec()).await;
        }
        for class in [Class::Consensus, Class::Requests] {
            for i in 0..FRAMES {
                let incoming = next(queue(b, class)).await;
                assert_eq!(incoming.frame, i.to_be_bytes().to_vec(), "{class:?}");
            }
        }
    });
}

/// Each side takes only the keys it configured: the accepting side, a
/// configured peer's; the dialing side, the one it dialed.
#[test]
fn a_key_not_configured_is_refused_on_either_side() {
    smol::block_on(async {
        let nodes = cluster(2);
        let (a, _) = &nodes[0];
        let (b, b_arrivals) = &nodes[1];
        // Node 9 knows node 2, but node 2 does not know node 9's key.
        let (stranger, _) = bind(9, any_port(), Limits::default());
        stranger.set_peers(vec![peer_of(2, b)]);
        send(&stranger, 2, Class::Consensus, 1, b"let me in".to_vec()).await;
        // Nor does it take a configured number with another node's key:
        // node 1 configured with node 9's key.
        let (impostor, _) = Quic::bind(Config {
            peers: vec![peer_of(2, b)],
            ..Config::new(1, secret(9), any_port())
        })
        .unwrap();
        send(&impostor, 2, Class::Consensus, 1, b"I am node 1".to_vec()).await;
        assert!(silent(b_arrivals, Duration::from_millis(500)).await);
        // Node 1 itself still gets through.
        send(a, 2, Class::Consensus, 1, b"node 1".to_vec()).await;
        assert_eq!(next(&b_arrivals.consensus).await.frame, b"node 1");
        // Node 1 believes node 2 has node 3's key, at node 2's address:
        // node 2 would take node 1, but node 1 refuses node 2.
        a.set_peers(vec![Peer {
            key: public_key(&secret(3)),
            ..peer_at(2, b.local_addr())
        }]);
        send(a, 2, Class::Consensus, 1, b"for node 3".to_vec()).await;
        assert!(silent(b_arrivals, Duration::from_millis(500)).await);
    });
}

#[test]
fn a_peer_shut_down_and_started_again_is_reachable_at_once() {
    smol::block_on(async {
        let mut nodes = cluster(2);
        let (b, _) = nodes.pop().unwrap();
        let (a, _) = nodes.pop().unwrap();
        let address = b.local_addr();
        send(&a, 2, Class::Consensus, 1, b"before".to_vec()).await;
        drop(b);

        // Node 1 sends first: its old connection is reset, and it redials.
        let (b, b_arrivals) = rebind(2, address).await;
        b.set_peers(vec![peer_of(1, &a)]);
        let started = Instant::now();
        let mut sent = 0u32;
        let arrived = loop {
            send(&a, 2, Class::Consensus, 1, sent.to_be_bytes().to_vec()).await;
            sent += 1;
            if let Some(incoming) =
                within(Duration::from_millis(20), b_arrivals.consensus.recv()).await
            {
                break incoming.unwrap();
            }
            assert!(
                started.elapsed() < Duration::from_secs(1),
                "unreachable after a restart"
            );
        };
        println!(
            "reached after {:?}, {sent} frames sent, frame {:?} first",
            started.elapsed(),
            arrived.frame
        );
    });
}

/// Frames queued for a peer not yet reachable wait for its connection,
/// but a liveness frame among them is dropped: it would say, late, that
/// its sender was alive when it was queued.
#[test]
fn a_liveness_frame_is_not_held_for_a_later_connection() {
    smol::block_on(async {
        let (a, _) = bind(1, any_port(), Limits::default());
        // Node 2's address, nothing listening there yet.
        let address = vacant_address();
        a.set_peers(vec![peer_at(2, address)]);
        send(&a, 2, Class::Liveness, 1, b"alive before".to_vec()).await;
        send(&a, 2, Class::Consensus, 1, b"held".to_vec()).await;
        smol::Timer::after(Duration::from_millis(200)).await;
        let (b, b_arrivals) = rebind(2, address).await;
        b.set_peers(vec![peer_of(1, &a)]);
        assert_eq!(next(&b_arrivals.consensus).await.frame, b"held");
        send(&a, 2, Class::Liveness, 1, b"alive now".to_vec()).await;
        assert_eq!(next(&b_arrivals.liveness).await.frame, b"alive now");
    });
}

#[test]
fn an_oversized_frame_is_refused() {
    smol::block_on(async {
        let small = Limits {
            consensus: 1 << 20,
            ..Limits::default()
        };
        let large = Limits {
            consensus: 8 << 20,
            ..Limits::default()
        };
        let (a, _) = bind(1, any_port(), large);
        let (b, b_arrivals) = bind(2, any_port(), small);
        a.set_peers(vec![peer_of(2, &b)]);
        b.set_peers(vec![peer_of(1, &a)]);
        // The sender refuses what its own limits refuse.
        assert_eq!(
            b.send(1, Class::Consensus, 1, vec![0; (1 << 20) + 1]),
            Err(Refused::TooLarge)
        );
        // The receiver stops a stream whose frame is over its bound, and
        // reads the others on.
        send(&a, 2, Class::Consensus, 1, vec![1; 2 << 20]).await;
        send(&a, 2, Class::Consensus, 2, b"small".to_vec()).await;
        let incoming = next(&b_arrivals.consensus).await;
        assert_eq!((incoming.stream, incoming.frame), (2, b"small".to_vec()));
        assert!(silent(&b_arrivals, Duration::from_millis(300)).await);
    });
}

#[test]
fn a_removed_peer_is_cut_off() {
    smol::block_on(async {
        let nodes = cluster(2);
        let (a, _) = &nodes[0];
        let (b, b_arrivals) = &nodes[1];
        send(a, 2, Class::Consensus, 1, b"before".to_vec()).await;
        assert_eq!(next(&b_arrivals.consensus).await.frame, b"before");
        b.set_peers(Vec::new());
        send(a, 2, Class::Consensus, 1, b"after".to_vec()).await;
        assert!(silent(b_arrivals, Duration::from_millis(500)).await);
        assert_eq!(
            b.send(1, Class::Consensus, 1, Vec::new()),
            Err(Refused::UnknownPeer)
        );
    });
}

#[test]
fn a_queue_to_an_unreachable_peer_fills() {
    smol::block_on(async {
        let (a, _) = bind(1, any_port(), Limits::default());
        // Nothing listens there.
        let silent = std::net::UdpSocket::bind(any_port()).unwrap();
        a.set_peers(vec![peer_at(2, silent.local_addr().unwrap())]);
        let frame = vec![0; 64 << 10];
        let mut queued = 0;
        while a.send(2, Class::Consensus, 1, frame.clone()).is_ok() {
            queued += frame.len();
            assert!(
                queued <= 4 * Limits::default().consensus + frame.len(),
                "the queue is unbounded"
            );
        }
        assert_eq!(
            a.send(2, Class::Consensus, 1, frame.clone()),
            Err(Refused::Full)
        );
        // Another class has its own queue.
        assert_eq!(a.send(2, Class::Liveness, 1, b"alive".to_vec()), Ok(()));
        assert!(
            within(Duration::from_millis(100), a.ready(2, Class::Consensus))
                .await
                .is_none()
        );
    });
}

#[test]
fn quiet_streams_finish_so_others_can_open() {
    smol::block_on(async {
        // Node 2 lets node 1 hold eight streams open at once, and node 1
        // finishes a stream quiet for 200 ms.
        let (a, _) = Quic::bind(Config {
            quiet: Duration::from_millis(200),
            ..Config::new(1, secret(1), any_port())
        })
        .unwrap();
        let (b, b_arrivals) = Quic::bind(Config {
            streams: 8,
            ..Config::new(2, secret(2), any_port())
        })
        .unwrap();
        a.set_peers(vec![peer_of(2, &b)]);
        b.set_peers(vec![peer_of(1, &a)]);
        for id in 0..8 {
            send(&a, 2, Class::Consensus, id, b"busy".to_vec()).await;
            assert_eq!(next(&b_arrivals.consensus).await.stream, id);
        }
        // A ninth stream opens once the first eight have gone quiet.
        let started = Instant::now();
        send(&a, 2, Class::Consensus, 8, b"ninth".to_vec()).await;
        let incoming = next(&b_arrivals.consensus).await;
        assert_eq!((incoming.stream, incoming.frame), (8, b"ninth".to_vec()));
        println!("the ninth stream opened after {:?}", started.elapsed());
        // A quiet stream's id opens a new stream when it is used again.
        send(&a, 2, Class::Consensus, 0, b"again".to_vec()).await;
        assert_eq!(next(&b_arrivals.consensus).await.frame, b"again");
    });
}

#[test]
fn a_quiet_stream_s_successor_keeps_its_order() {
    smol::block_on(async {
        let (a, _) = Quic::bind(Config {
            quiet: Duration::from_millis(50),
            ..Config::new(1, secret(1), any_port())
        })
        .unwrap();
        let (b, b_arrivals) = bind(2, any_port(), Limits::default());
        a.set_peers(vec![peer_of(2, &b)]);
        b.set_peers(vec![peer_of(1, &a)]);
        // Nothing is consumed while three bursts go out, each on a new
        // stream for the same id: the first burst's reader waits on a full
        // arrival queue, holding frames its successors must not pass.
        const BURST: u32 = 1500;
        for burst in 0..3 {
            for i in burst * BURST..(burst + 1) * BURST {
                send(&a, 2, Class::Requests, 5, i.to_be_bytes().to_vec()).await;
            }
            smol::Timer::after(Duration::from_millis(200)).await;
        }
        // A slow consumer frees one place at a time, which the waiting
        // readers would take in turns.
        for i in 0..3 * BURST {
            let incoming = next(&b_arrivals.requests).await;
            assert_eq!(incoming.frame, i.to_be_bytes().to_vec());
            smol::Timer::after(Duration::from_micros(50)).await;
        }
    });
}
