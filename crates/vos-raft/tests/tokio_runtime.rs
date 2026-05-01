//! Smoke test for the [`TokioClock`] adapter.
//!
//! Exercises [`Worker::spawn_with_tokio_runtime`] — the helper
//! that drives the worker future on a tokio current-thread
//! runtime with `enable_time()`, which is what `TokioClock`'s
//! `Sleep` future requires. The plain [`Worker::spawn_with`]
//! would panic on the first poll because `futures-executor`
//! has no timer driver.

#![cfg(all(feature = "std", feature = "tokio"))]

use std::sync::Arc;

use vos_raft::{
    AppendEntriesReq, Config, InstallSnapshotReq, MemStorage, RequestVoteReq, Role,
    StdRng, TokioClock, Transport, Worker,
};

struct NoopT;
#[derive(Debug)]
struct NoopE;
impl core::fmt::Display for NoopE {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "noop")
    }
}
impl std::error::Error for NoopE {}
impl Transport<u16> for NoopT {
    type Error = NoopE;
    async fn send_append(
        &self,
        _: u16,
        _: AppendEntriesReq<u16>,
    ) -> Result<vos_raft::AppendEntriesResp, NoopE> {
        Err(NoopE)
    }
    async fn send_vote(
        &self,
        _: u16,
        _: RequestVoteReq<u16>,
    ) -> Result<vos_raft::RequestVoteResp, NoopE> {
        Err(NoopE)
    }
    async fn send_install(
        &self,
        _: u16,
        _: InstallSnapshotReq<u16>,
    ) -> Result<vos_raft::InstallSnapshotResp, NoopE> {
        Err(NoopE)
    }
}

#[test]
fn solo_cluster_self_elects_with_tokio_clock() {
    let storage = MemStorage::<u16>::new();
    let transport = Arc::new(NoopT);
    let mut cfg = Config::new(0xAAAA, vec![0xAAAA], [0xC0; 32]);
    cfg.election_timeout_ms = (10, 30);
    cfg.heartbeat_interval_ms = 5;

    let worker = Worker::spawn_with_tokio_runtime(
        storage,
        transport,
        cfg,
        (),
        TokioClock,
        StdRng::from_entropy(),
    );

    // Solo cluster wins its first election (quorum = 1) under
    // any working clock — the value of this test is that
    // `TokioClock::sleep_until` actually fires (without the
    // tokio runtime built inside the spawn helper, the first
    // poll panics with "no Tokio reactor running").
    let until = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while worker.role() != Role::Leader {
        assert!(
            std::time::Instant::now() < until,
            "solo cluster failed to self-elect under TokioClock + spawn_with_tokio_runtime",
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }

    worker.shutdown();
}

/// Pins the documented incompatibility: `Worker::spawn_with`
/// drives the worker on `futures-executor`, which has no
/// timer driver. `TokioClock`'s `Sleep` future panics on the
/// first poll with "no Tokio reactor running". This test asserts
/// the worker thread terminates without becoming Leader — the
/// panic kills the worker thread but doesn't propagate up to
/// the test. If this test ever starts passing (becoming Leader),
/// the worker probably gained an internal tokio runtime and the
/// docs should be updated.
#[test]
fn spawn_with_panics_with_tokio_clock_no_runtime() {
    let storage = MemStorage::<u16>::new();
    let transport = Arc::new(NoopT);
    let mut cfg = Config::new(0xAAAA, vec![0xAAAA], [0xC0; 32]);
    cfg.election_timeout_ms = (10, 30);
    cfg.heartbeat_interval_ms = 5;

    let worker = Worker::spawn_with(
        storage,
        transport,
        cfg,
        (),
        TokioClock,
        StdRng::from_entropy(),
    );

    // Give the worker thread enough time to poll its first
    // `sleep_until` and panic. Then verify it never reached
    // Leader: the panic on the first poll prevented the
    // election from completing.
    std::thread::sleep(std::time::Duration::from_millis(200));
    assert_ne!(
        worker.role(),
        Role::Leader,
        "spawn_with + TokioClock without a tokio runtime should panic on first poll, \
         not silently elect a leader",
    );
    // Drop the worker without calling shutdown; the thread has
    // already aborted. Calling shutdown would join a thread that
    // panicked, which is fine but adds noise.
    drop(worker);
}
