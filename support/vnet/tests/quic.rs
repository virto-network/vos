//! Nodes on localhost over QUIC.

mod common;

use std::time::{Duration, Instant};

use common::*;
use vnet::quic::{Config, Quic};
use vnet::{Network, Peer, Refused};

#[test]
fn three_nodes_exchange_frames_on_every_class() {
    smol::block_on(async {
        let nodes = cluster(3);
        let others = |number: u8| (1..=3).filter(move |other| *other != number);
        // A liveness frame never waits for a connection: connect first.
        for ((quic, _), number) in nodes.iter().zip(1..) {
            for to in others(number) {
                send(quic, key(to), CONSENSUS, 0, b"hello".to_vec()).await;
            }
        }
        for (_, arrivals) in &nodes {
            for _ in 0..2 {
                assert_eq!(next(arrivals.queue(CONSENSUS)).await.frame, b"hello");
            }
        }
        for ((quic, _), number) in nodes.iter().zip(1..) {
            for to in others(number) {
                for class in ALL {
                    let frame = format!("{class} to {to}").into_bytes();
                    send(quic, key(to), class, u64::from(to) * 10, frame).await;
                }
            }
        }
        for ((_, arrivals), number) in nodes.iter().zip(1u8..) {
            for class in ALL {
                let mut from = Vec::new();
                for _ in 0..2 {
                    let incoming = next(arrivals.queue(class)).await;
                    assert_eq!(incoming.frame, format!("{class} to {number}").into_bytes());
                    assert_eq!(incoming.stream, u64::from(number) * 10);
                    from.push(incoming.from);
                }
                from.sort();
                let mut others: Vec<_> = others(number).map(key).collect();
                others.sort();
                assert_eq!(from, others, "node {number}, class {class}");
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
            send(a, key(2), CONSENSUS, 7, i.to_be_bytes().to_vec()).await;
            send(a, key(2), REQUESTS, 8, i.to_be_bytes().to_vec()).await;
        }
        for class in [CONSENSUS, REQUESTS] {
            for i in 0..FRAMES {
                let incoming = next(b.queue(class)).await;
                assert_eq!(incoming.frame, i.to_be_bytes().to_vec(), "class {class}");
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
        let (stranger, _) = bind(9);
        stranger.set_peers(vec![peer_of(b)]);
        send(&stranger, key(2), CONSENSUS, 1, b"let me in".to_vec()).await;
        assert!(silent(b_arrivals, Duration::from_millis(500)).await);
        // Node 1 itself still gets through.
        send(a, key(2), CONSENSUS, 1, b"node 1".to_vec()).await;
        assert_eq!(next(b_arrivals.queue(CONSENSUS)).await.frame, b"node 1");
        // Node 1 believes node 3 is at node 2's address: node 2 would take
        // node 1, but node 1 refuses node 2's key.
        a.set_peers(vec![Peer {
            key: key(3),
            ..peer_at(2, b.local_addr())
        }]);
        send(a, key(3), CONSENSUS, 1, b"for node 3".to_vec()).await;
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
        send(&a, key(2), CONSENSUS, 1, b"before".to_vec()).await;
        drop(b);

        // Node 1 sends first: its old connection is closed, or reset, and
        // it redials.
        let (b, b_arrivals) = rebind(2, address).await;
        b.set_peers(vec![peer_of(&a)]);
        let started = Instant::now();
        let mut sent = 0u32;
        let arrived = loop {
            send(&a, key(2), CONSENSUS, 1, sent.to_be_bytes().to_vec()).await;
            sent += 1;
            if let Some(incoming) = within(
                Duration::from_millis(20),
                b_arrivals.queue(CONSENSUS).recv(),
            )
            .await
            {
                break incoming.unwrap();
            }
            // Well within the 30 s an old connection would take to idle
            // out, with room for a loaded host.
            assert!(
                started.elapsed() < Duration::from_secs(5),
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
/// but one of a class with an age, waiting longer, is dropped: a liveness
/// frame would say, late, that its sender was alive when it was queued.
#[test]
fn a_frame_older_than_its_class_s_age_is_dropped() {
    smol::block_on(async {
        let (a, _) = bind(1);
        // Node 2's address, nothing listening there yet.
        let address = vacant_address();
        a.set_peers(vec![peer_at(2, address)]);
        send(&a, key(2), LIVENESS, 1, b"alive before".to_vec()).await;
        send(&a, key(2), CONSENSUS, 1, b"held".to_vec()).await;
        smol::Timer::after(LIVENESS_AGE + Duration::from_millis(500)).await;
        let (b, b_arrivals) = rebind(2, address).await;
        b.set_peers(vec![peer_of(&a)]);
        assert_eq!(next(b_arrivals.queue(CONSENSUS)).await.frame, b"held");
        send(&a, key(2), LIVENESS, 1, b"alive now".to_vec()).await;
        assert_eq!(next(b_arrivals.queue(LIVENESS)).await.frame, b"alive now");
    });
}

/// A frame of a class with an age, queued before its peer is reachable,
/// still goes once it is, while younger than its age: the age counts the
/// wait, not whether a connection was there.
#[test]
fn a_frame_younger_than_its_class_s_age_waits_for_the_connection() {
    smol::block_on(async {
        let mut specs = specs(MAX_FRAME);
        specs[usize::from(LIVENESS)].max_age = Some(Duration::from_secs(30));
        let (a, _) = Quic::bind(Config {
            classes: vnet::Classes::new(specs).unwrap(),
            ..config(1)
        })
        .unwrap();
        let address = vacant_address();
        a.set_peers(vec![peer_at(2, address)]);
        send(&a, key(2), LIVENESS, 1, b"alive, queued".to_vec()).await;
        smol::Timer::after(Duration::from_millis(200)).await;
        let (b, b_arrivals) = rebind(2, address).await;
        b.set_peers(vec![peer_of(&a)]);
        assert_eq!(
            next(b_arrivals.queue(LIVENESS)).await.frame,
            b"alive, queued"
        );
    });
}

/// Of a key listed twice, the last counts; the node's own key is left out.
#[test]
fn peers_are_keys_the_last_listing_counting() {
    smol::block_on(async {
        let nodes = cluster(2);
        let (a, _) = &nodes[0];
        let (b, b_arrivals) = &nodes[1];
        a.set_peers(vec![peer_of(a), peer_at(2, vacant_address()), peer_of(b)]);
        assert_eq!(
            a.send(a.key(), CONSENSUS, 1, Vec::new()),
            Err(Refused::UnknownPeer)
        );
        send(a, key(2), CONSENSUS, 1, b"to the last".to_vec()).await;
        assert_eq!(
            next(b_arrivals.queue(CONSENSUS)).await.frame,
            b"to the last"
        );
    });
}

#[test]
fn an_oversized_frame_is_refused() {
    smol::block_on(async {
        let consensus = |bound| {
            let mut max_frame = MAX_FRAME;
            max_frame[usize::from(CONSENSUS)] = bound;
            with_frames(max_frame)
        };
        let ((a, _), (b, b_arrivals)) = pair(
            Config {
                classes: consensus(8 << 20),
                ..config(1)
            },
            Config {
                classes: consensus(1 << 20),
                ..config(2)
            },
        );
        // The sender refuses what its own limits refuse.
        assert_eq!(
            b.send(key(1), CONSENSUS, 1, vec![0; (1 << 20) + 1]),
            Err(Refused::TooLarge)
        );
        // The receiver stops a stream whose frame is over its bound, and
        // reads the others on.
        send(&a, key(2), CONSENSUS, 1, vec![1; 2 << 20]).await;
        send(&a, key(2), CONSENSUS, 2, b"small".to_vec()).await;
        let incoming = next(b_arrivals.queue(CONSENSUS)).await;
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
        send(a, key(2), CONSENSUS, 1, b"before".to_vec()).await;
        assert_eq!(next(b_arrivals.queue(CONSENSUS)).await.frame, b"before");
        b.set_peers(Vec::new());
        send(a, key(2), CONSENSUS, 1, b"after".to_vec()).await;
        assert!(silent(b_arrivals, Duration::from_millis(500)).await);
        assert_eq!(
            b.send(key(1), CONSENSUS, 1, Vec::new()),
            Err(Refused::UnknownPeer)
        );
    });
}

#[test]
fn a_queue_to_an_unreachable_peer_fills() {
    smol::block_on(async {
        let (a, _) = bind(1);
        // Nothing listens there.
        let silent = std::net::UdpSocket::bind(any_port()).unwrap();
        a.set_peers(vec![peer_at(2, silent.local_addr().unwrap())]);
        let frame = vec![0; 64 << 10];
        let mut queued = 0;
        while a.send(key(2), CONSENSUS, 1, frame.clone()).is_ok() {
            queued += frame.len();
            assert!(
                queued <= 4 * MAX_FRAME[usize::from(CONSENSUS)] + frame.len(),
                "the queue is unbounded"
            );
        }
        assert_eq!(
            a.send(key(2), CONSENSUS, 1, frame.clone()),
            Err(Refused::Full)
        );
        // Another class has its own queue.
        assert_eq!(a.send(key(2), LIVENESS, 1, b"alive".to_vec()), Ok(()));
        assert!(
            within(Duration::from_millis(100), a.ready(key(2), CONSENSUS))
                .await
                .is_none()
        );
    });
}

/// Each class's queue to a peer takes frames while it holds less than
/// four of its largest frames (one, for Bulk), counting each frame's bytes
/// and 64 more.
#[test]
fn each_class_s_queue_to_a_peer_holds_its_budget() {
    let (a, _) = Quic::bind(Config {
        classes: with_frames([1000, 2000, 3000, 4000]),
        ..config(1)
    })
    .unwrap();
    // Nothing answers there.
    let silent = std::net::UdpSocket::bind(any_port()).unwrap();
    a.set_peers(vec![peer_at(2, silent.local_addr().unwrap())]);
    let taken = |class| {
        (0..)
            .take_while(|_| a.send(key(2), class, 1, vec![0; 100]).is_ok())
            .count()
    };
    // A frame costs 164: 4,000, 8,000, 12,000 and 4,000 bytes' budgets.
    assert_eq!(ALL.map(taken), [25, 49, 74, 25]);
}

#[test]
fn quiet_streams_finish_so_others_can_open() {
    smol::block_on(async {
        // Node 2 lets node 1 hold eight streams open at once, and node 1
        // finishes a stream quiet for 200 ms.
        let ((a, _), (_b, b_arrivals)) = pair(
            Config {
                quiet: Duration::from_millis(200),
                ..config(1)
            },
            Config {
                streams: 8,
                ..config(2)
            },
        );
        for id in 0..8 {
            send(&a, key(2), CONSENSUS, id, b"busy".to_vec()).await;
            assert_eq!(next(b_arrivals.queue(CONSENSUS)).await.stream, id);
        }
        // A ninth stream opens once the first eight have gone quiet.
        let started = Instant::now();
        send(&a, key(2), CONSENSUS, 8, b"ninth".to_vec()).await;
        let incoming = next(b_arrivals.queue(CONSENSUS)).await;
        assert_eq!((incoming.stream, incoming.frame), (8, b"ninth".to_vec()));
        println!("the ninth stream opened after {:?}", started.elapsed());
        // A quiet stream's id opens a new stream when it is used again.
        send(&a, key(2), CONSENSUS, 0, b"again".to_vec()).await;
        assert_eq!(next(b_arrivals.queue(CONSENSUS)).await.frame, b"again");
    });
}

#[test]
fn a_quiet_stream_s_successor_keeps_its_order() {
    smol::block_on(async {
        let ((a, _), (_b, b_arrivals)) = pair(
            Config {
                quiet: Duration::from_millis(50),
                ..config(1)
            },
            config(2),
        );
        // Nothing is consumed while three bursts go out, each on a new
        // stream for the same id: the first burst's reader waits on a full
        // arrival queue, holding frames its successors must not pass.
        const BURST: u32 = 1500;
        for burst in 0..3 {
            for i in burst * BURST..(burst + 1) * BURST {
                send(&a, key(2), REQUESTS, 5, i.to_be_bytes().to_vec()).await;
            }
            smol::Timer::after(Duration::from_millis(200)).await;
        }
        // A slow consumer frees one place at a time, which the waiting
        // readers would take in turns.
        for i in 0..3 * BURST {
            let incoming = next(b_arrivals.queue(REQUESTS)).await;
            assert_eq!(incoming.frame, i.to_be_bytes().to_vec());
            smol::Timer::after(Duration::from_micros(50)).await;
        }
    });
}
