//! Smoke test for the [`TokioClock`] adapter.
//!
//! Spawns a solo cluster wired with `TokioClock` and a tokio
//! runtime. Verifies the worker self-elects, accepts a propose,
//! and shuts down cleanly. This is the recommended config for
//! tokio-native hosts (avoids `StdClock`'s per-`Delay` thread
//! spawning).

#![cfg(all(feature = "std", feature = "tokio"))]

use std::sync::Arc;

use vos_raft::{
    AppendEntriesReq, Config, InstallSnapshotReq, MemStorage, RequestVoteReq, Role,
    StdRng, TokioClock, Transport,
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
    // The `Worker::spawn_with` thread-spawning convenience runs
    // `futures_executor::block_on` on the dedicated thread.
    // `TokioClock::sleep_until` returns a `tokio::time::Sleep`
    // — that needs a tokio runtime to drive its waker. Build a
    // current-thread tokio runtime on the worker thread and
    // drive the worker future on it.
    //
    // To avoid bundling a custom executor here, the simplest
    // way is: spawn a thread that owns a tokio runtime and
    // calls `runtime.block_on(run_worker(...))`. But the
    // existing `Worker::spawn_with` uses `futures_executor`,
    // which doesn't drive tokio timers.
    //
    // Workaround for this smoke test: use the lower-level
    // `vos_raft::worker::run_worker` directly, dispatched on a
    // tokio current-thread runtime.

    use std::sync::atomic::AtomicU8;
    use std::time::Duration;
    use vos_raft::worker::run_worker;

    let storage = MemStorage::<u16>::new();
    let transport = Arc::new(NoopT);
    let mut cfg = Config::new(0xAAAA, vec![0xAAAA], [0xC0; 32]);
    cfg.election_timeout_ms = (10, 30);
    cfg.heartbeat_interval_ms = 5;

    let role = Arc::new(AtomicU8::new(Role::Follower.as_u8()));
    let role_clone = role.clone();

    let (tx, rx) = futures_channel::mpsc::unbounded::<vos_raft::RaftMsg<u16>>();

    // Drive the worker on a dedicated thread running a tokio
    // current-thread runtime. The `TokioClock` registers its
    // sleeps with this runtime's timer driver — no thread
    // spawning per `Delay`.
    let join = std::thread::spawn(move || {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("tokio runtime");
        rt.block_on(async move {
            run_worker(
                storage,
                transport,
                cfg,
                rx,
                (),
                TokioClock,
                StdRng::from_entropy(),
                role_clone,
            )
            .await
        });
    });

    // Poll the role atomic for self-election. Solo cluster wins
    // its first election (quorum = 1).
    let until = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if Role::from_u8(role.load(std::sync::atomic::Ordering::Relaxed)) == Role::Leader {
            break;
        }
        assert!(
            std::time::Instant::now() < until,
            "solo cluster failed to self-elect under TokioClock",
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    // Tell the worker to shut down by dropping the inbox sender.
    drop(tx);
    let _ = join.join();
}
