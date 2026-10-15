//! Small consensus frames' latency, alone and beside bulk frames to the
//! same peer, in a process of its own so no other test shares its
//! executor.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::*;
use vos_net::quic::Quic;
use vos_net::{Arrivals, Class};

/// Small consensus frames' round of latencies, each the time from send to
/// arrival.
async fn latencies(a: &Quic, b: &Arrivals, count: usize) -> Vec<Duration> {
    let started = Instant::now();
    let mut latencies = Vec::with_capacity(count);
    for i in 0..count {
        let sent = started.elapsed().as_nanos() as u64;
        let mut frame = sent.to_be_bytes().to_vec();
        frame.resize(200, 0);
        send(a, 2, Class::Consensus, i as u64 % 16, frame).await;
        let incoming = next(&b.consensus).await;
        let sent = u64::from_be_bytes(incoming.frame[..8].try_into().unwrap());
        latencies.push(started.elapsed() - Duration::from_nanos(sent));
        smol::Timer::after(Duration::from_millis(1)).await;
    }
    latencies.sort();
    latencies
}

/// A bulk frame's bytes.
const BULK_FRAME: usize = 4 << 20;

fn percentile(sorted: &[Duration], percent: usize) -> Duration {
    sorted[(sorted.len() * percent / 100).min(sorted.len() - 1)]
}

#[test]
fn bulk_frames_do_not_hold_up_consensus() {
    smol::block_on(async {
        let mut nodes = cluster(2);
        let (_b, b) = nodes.pop().unwrap();
        let (a, _) = nodes.pop().unwrap();
        let a = Arc::new(a);
        const COUNT: usize = 500;
        // Warm the connection.
        latencies(&a, &b, 20).await;
        let alone = latencies(&a, &b, COUNT).await;

        let bulk = smol::spawn({
            let a = Arc::clone(&a);
            async move {
                let mut sent = 0usize;
                loop {
                    send(&*a, 2, Class::Bulk, sent as u64, vec![7; BULK_FRAME]).await;
                    sent += 1;
                }
            }
        });
        let moved = Arc::new(AtomicUsize::new(0));
        let drain = smol::spawn({
            let bulk = b.bulk.clone();
            let moved = Arc::clone(&moved);
            async move {
                while let Ok(incoming) = bulk.recv().await {
                    moved.fetch_add(incoming.frame.len(), Ordering::Relaxed);
                }
            }
        });
        let started = Instant::now();
        let beside = latencies(&a, &b, COUNT).await;
        let elapsed = started.elapsed();
        drop(bulk);
        drop(drain);
        let bytes = moved.load(Ordering::Relaxed);
        println!(
            "consensus alone: p50 {:?} p99 {:?}; beside bulk: p50 {:?} p99 {:?}; bulk moved {} MiB in {elapsed:?}",
            percentile(&alone, 50),
            percentile(&alone, 99),
            percentile(&beside, 50),
            percentile(&beside, 99),
            bytes >> 20,
        );
        assert!(bytes >= 4 * BULK_FRAME, "the bulk frames barely moved");
        // A consensus frame held behind bulk frames waits while at least
        // one goes out whole, so the bound is a share of the time the link
        // takes to move one. What a loaded machine adds grows with that
        // time, and stays under a tenth of it.
        let frame_time = elapsed / (bytes / BULK_FRAME) as u32;
        let bound = (frame_time / 4).max(Duration::from_millis(5));
        assert!(
            percentile(&beside, 99) <= percentile(&alone, 99) + bound,
            "bulk moved the consensus p99 by more than {bound:?}, a quarter of a bulk frame's {frame_time:?}"
        );
    });
}
