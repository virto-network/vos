//! Fault-injection tests for the [`Storage`] error path.
//!
//! Every `state.storage.*().await?` in the worker propagates an
//! `Err` to its caller. None of the existing tests trigger that
//! path — `MemStorage::Error = Infallible` and `RedbStorage` only
//! errors on actual disk failure. This file pins down what the
//! worker actually does when storage returns `Err`:
//!
//! - **Inbound RPC handler** (`handle_append_entries` etc.):
//!   error bubbles up to `handle_msg`, which silently drops the
//!   `oneshot` reply. The peer's RPC times out (looks like a
//!   dropped packet). The next inbound RPC is unaffected.
//! - **Propose**: `handle_propose` maps storage errors to
//!   `ProposeError::Storage(())` which surfaces back to the
//!   caller. The worker stays alive.
//! - **Outbound RPC response handler** (`handle_append_response`):
//!   storage error during the term-bump-then-step-down path
//!   bubbles up to `handle_rpc_outcome` where it's discarded.
//!   The worker continues with stale meta on disk.
//! - **Initial `load_meta`** (in `run_worker`): worker silently
//!   exits — the caller's `Worker::shutdown` joins immediately.
//!   This is a known limitation; a future commit will surface
//!   the failure through a return value.

#![cfg(feature = "std")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_executor::block_on;
use vos_raft::{
    AppendEntriesReq, ApplySink, Clock, InstallSnapshotReq, LogEntry, MemStorage, Meta,
    ProposeError, RequestVoteReq, Rng, Role, StdClock, StdRng, Storage, Transport, Worker,
    WriteBatch,
};

/// Storage wrapper that delegates to an inner backend but
/// can be configured to return `Err` for the next N calls of
/// each method. Useful for asserting that the worker handles
/// transient errors as "no-op + retry later" rather than
/// crashing.
pub struct FaultStorage<S: Storage<u16> + Sync> {
    inner: S,
    /// `commit_batch` will return `Err` for this many subsequent
    /// calls.
    fail_commit: Arc<AtomicU64>,
    /// `load_meta` will return `Err` for this many subsequent
    /// calls.
    fail_load_meta: Arc<AtomicU64>,
    /// `term_at` will return `Err` for this many subsequent
    /// calls. Lets us exercise the AppendEntries consistency-check
    /// failure path.
    fail_term_at: Arc<AtomicU64>,
    /// `entries` will return `Err` for this many subsequent
    /// calls. Lets us exercise the heartbeat-construction
    /// failure path.
    fail_entries: Arc<AtomicU64>,
}

impl<S: Storage<u16> + Sync> FaultStorage<S> {
    pub fn new(inner: S) -> Self {
        Self {
            inner,
            fail_commit: Arc::new(AtomicU64::new(0)),
            fail_load_meta: Arc::new(AtomicU64::new(0)),
            fail_term_at: Arc::new(AtomicU64::new(0)),
            fail_entries: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn fail_commit_handle(&self) -> Arc<AtomicU64> {
        self.fail_commit.clone()
    }

    pub fn fail_load_meta_handle(&self) -> Arc<AtomicU64> {
        self.fail_load_meta.clone()
    }

    pub fn fail_term_at_handle(&self) -> Arc<AtomicU64> {
        self.fail_term_at.clone()
    }

    #[allow(dead_code)]
    pub fn fail_entries_handle(&self) -> Arc<AtomicU64> {
        self.fail_entries.clone()
    }
}

#[derive(Debug)]
pub struct FaultErr;

impl core::fmt::Display for FaultErr {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "injected storage fault")
    }
}

impl std::error::Error for FaultErr {}

/// Either an injected fault or a passthrough error from the inner
/// backend. Squashes both into the test-side `FaultErr` so the
/// `Storage` impl bound stays clean. `Storage::Error` only
/// requires `Debug + Send + Sync + 'static` — no `std::error::Error`.
fn map_err<E: core::fmt::Debug>(_: E) -> FaultErr {
    FaultErr
}

impl<S: Storage<u16> + Sync> Storage<u16> for FaultStorage<S> {
    type Error = FaultErr;

    fn last_index(&self) -> u64 {
        self.inner.last_index()
    }
    fn last_term(&self) -> u64 {
        self.inner.last_term()
    }
    fn snap_last_index(&self) -> u64 {
        self.inner.snap_last_index()
    }
    fn snap_last_term(&self) -> u64 {
        self.inner.snap_last_term()
    }
    async fn term_at(&self, index: u64) -> Result<Option<u64>, Self::Error> {
        if take_fault_budget(&self.fail_term_at) {
            return Err(FaultErr);
        }
        self.inner.term_at(index).await.map_err(map_err)
    }
    async fn entries(&self, start: u64, end: u64) -> Result<Vec<LogEntry<u16>>, Self::Error> {
        if take_fault_budget(&self.fail_entries) {
            return Err(FaultErr);
        }
        self.inner.entries(start, end).await.map_err(map_err)
    }
    async fn read_state(&self) -> Result<Vec<u8>, Self::Error> {
        self.inner.read_state().await.map_err(map_err)
    }
    async fn load_meta(&self) -> Result<Meta<u16>, Self::Error> {
        if take_fault_budget(&self.fail_load_meta) {
            return Err(FaultErr);
        }
        self.inner.load_meta().await.map_err(map_err)
    }
    async fn commit_batch(&mut self, batch: WriteBatch<u16>) -> Result<(), Self::Error> {
        if take_fault_budget(&self.fail_commit) {
            return Err(FaultErr);
        }
        self.inner.commit_batch(batch).await.map_err(map_err)
    }
}

/// Atomically consume one fault from `budget`. Returns `true`
/// if the call should fail.
///
/// Naive `fetch_sub` + post-hoc underflow guard races: under
/// heavy contention with `budget == 1`, two concurrent callers
/// can both observe a positive `prev` (one sees 1, the other
/// sees `u64::MAX` from the underflow flicker before the store
/// repairs it) and BOTH fail when only one should. CAS loop
/// closes the window — `compare_exchange` only succeeds for
/// one caller per decrement.
fn take_fault_budget(budget: &AtomicU64) -> bool {
    loop {
        let cur = budget.load(Ordering::Relaxed);
        if cur == 0 {
            return false;
        }
        if budget
            .compare_exchange_weak(cur, cur - 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            return true;
        }
        // Lost the CAS — another thread mutated; retry.
    }
}

// ── Helpers ────────────────────────────────────────────────────

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

fn solo_cfg() -> vos_raft::Config<u16> {
    let mut c = vos_raft::Config::new(0xAAAA, vec![0xAAAA], [0u8; 32]);
    // Long election window — we want to observe storage fault
    // behavior without a spontaneous election interfering.
    c.election_timeout_ms = (60_000, 120_000);
    c.heartbeat_interval_ms = 30_000;
    c
}

fn multi_cfg() -> vos_raft::Config<u16> {
    let mut c = vos_raft::Config::new(0xAAAA, vec![0xAAAA, 0xBBBB, 0xCCCC], [0u8; 32]);
    c.election_timeout_ms = (60_000, 120_000);
    c.heartbeat_interval_ms = 30_000;
    c
}

// ── Tests ──────────────────────────────────────────────────────

/// A storage `Err` during `handle_append_entries` propagates back
/// through `handle_msg` which silently drops the reply oneshot.
/// The caller observing this would see a hung future / timeout —
/// equivalent to a dropped network packet, which is exactly the
/// behavior Raft tolerates.
#[test]
fn append_entries_returns_no_reply_on_storage_failure() {
    let storage = FaultStorage::new(MemStorage::<u16>::new());
    let fail = storage.fail_commit_handle();
    // First commit_batch (the meta-only persist on accepting the
    // term bump or the truncate+append batch) will fail.
    fail.store(1, Ordering::Relaxed);

    let worker = Worker::spawn_with(
        storage,
        Arc::new(NoopT),
        multi_cfg(),
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    let h = worker.handler();

    // Send an inbound AppendEntries. The handler will try to
    // `commit_batch` the meta change (term 0 → 5) and the empty
    // log update; the injected fault returns Err. The handler
    // returns Err, and `handle_msg` drops the reply silently.
    let fut = h.handle_inbound_append(
        0xBBBB,
        AppendEntriesReq {
            leader: 0xBBBB,
            term: 5,
            prev_log_index: 0,
            prev_log_term: 0,
            leader_commit: 0,
            entries: vec![],
        },
    );
    // Use a bounded block_on so a hung future doesn't hang the
    // test forever. We expect either the default fallback
    // response (success=false at the requested term) or for the
    // future to never resolve. The handler currently fabricates
    // the fallback in `WorkerHandle::handle_inbound_append` when
    // the inbox send fails OR the oneshot's sender drops without
    // sending — the latter is what we trigger here.
    let resp =
        run_with_timeout(fut, Duration::from_millis(200)).expect("handle returned");

    assert!(
        !resp.success,
        "follower must not report success when its meta write failed",
    );

    // ----- Caveat on what this test can and can't verify ------
    //
    // Even though the storage `commit_batch` returned `Err`, the
    // worker's IN-MEMORY `state.meta.current_term` was already
    // mutated to 5 before the call (see `handle_append_entries`
    // — the term bump happens before the storage call). So
    // `worker.snapshot().current_term` reads back as 5, not 0.
    // The disk-side rollback (no META_TERM write to the storage
    // backend) is what the test is really pinning, but the
    // public `snapshot()` API surfaces only the in-memory view.
    //
    // We therefore can't *strongly* assert "the meta wasn't
    // persisted" through the public API — but the fact that the
    // SECOND AppendEntries below (after fault budget exhaustion)
    // does succeed indicates the worker is in a usable state,
    // and any hypothetical regression that silently treated the
    // first call as successful would either deadlock the test
    // or change the success outcome of the second call.
    //
    // This in-memory-vs-disk divergence is itself documented as
    // a known caveat — see the worker's handler logic and the
    // CHANGELOG entry on storage-error semantics.

    // Subsequent RPC works after the fault budget is exhausted.
    fail.store(0, Ordering::Relaxed);
    let resp2 = block_on(h.handle_inbound_append(
        0xBBBB,
        AppendEntriesReq {
            leader: 0xBBBB,
            term: 5,
            prev_log_index: 0,
            prev_log_term: 0,
            leader_commit: 0,
            entries: vec![],
        },
    ));
    assert!(resp2.success, "second call (no fault) must succeed");

    worker.shutdown();
}

/// A propose that hits a storage fault surfaces as
/// `ProposeError::Storage` to the caller. The worker stays
/// alive; subsequent proposes work once the fault budget is
/// exhausted.
#[test]
fn propose_storage_failure_surfaces_to_caller_and_worker_recovers() {
    // Solo cluster — self-elects to Leader so propose is on the
    // leader path. We need to skip past the election's
    // commit_batch (which writes the term bump) before triggering
    // the fault, so use a separate seeding step.

    // Manually elect first by feeding the worker a successful
    // run, then schedule the fault for the second commit_batch
    // (the propose's append).
    let storage = FaultStorage::new(MemStorage::<u16>::new());
    let fail = storage.fail_commit_handle();

    // Tight timeout — solo cluster self-elects fast.
    let mut cfg = solo_cfg();
    cfg.election_timeout_ms = (10, 30);

    let worker = Worker::spawn_with(
        storage,
        Arc::new(NoopT),
        cfg,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    let h = worker.handler();

    // Wait for self-election to complete (1 commit_batch for
    // term bump / voted_for, may also do a heartbeat-related
    // one).
    let until = std::time::Instant::now() + Duration::from_secs(2);
    while worker.role() != Role::Leader {
        assert!(
            std::time::Instant::now() < until,
            "solo cluster must self-elect",
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    // Schedule the next commit_batch to fail. The next propose
    // triggers a commit_batch for the appended entry.
    fail.store(1, Ordering::Relaxed);

    let r = block_on(h.propose(b"will-fail".to_vec()));
    match r {
        Err(ProposeError::Storage(())) => {}
        other => panic!("expected ProposeError::Storage, got {other:?}"),
    }

    // Worker is still alive. Subsequent propose succeeds once
    // the fault budget is exhausted.
    fail.store(0, Ordering::Relaxed);
    let r2 = block_on(h.propose(b"will-succeed".to_vec()));
    assert!(r2.is_ok(), "second propose after fault must succeed: got {r2:?}");

    worker.shutdown();
}

/// A `load_meta` failure during worker startup is now
/// observable via [`Worker::init_failed`]: the worker thread
/// exits with `Err` from `run_worker`, which the spawn helper
/// catches and surfaces through the shared atomic flag.
#[test]
fn worker_signals_init_failure_on_load_meta_error() {
    let storage = FaultStorage::new(MemStorage::<u16>::new());
    let fail = storage.fail_load_meta_handle();
    // Fail the very first load_meta call (the one in run_worker).
    fail.store(1, Ordering::Relaxed);

    let worker = Worker::spawn_with(
        storage,
        Arc::new(NoopT),
        solo_cfg(),
        (),
        StdClock,
        StdRng::from_entropy(),
    );

    // The worker thread exits promptly on the load_meta error.
    // Give it a moment to set the flag.
    std::thread::sleep(Duration::from_millis(50));

    // STRONG signal: init_failed reports true. This is the new
    // observability surface — pre-RD3 the host could only infer
    // failure from snapshot() returning None, which is ambiguous
    // (could mean the worker is busy, the channel is full, etc).
    assert!(
        worker.init_failed(),
        "init failure flag must be set after load_meta returns Err",
    );

    // Happy-path complement: with no fault, init_failed stays
    // false. Ship this assertion alongside the failure case so
    // a regression that defaults the flag to true would be
    // caught.
    {
        let healthy_storage = FaultStorage::new(MemStorage::<u16>::new());
        let healthy_worker = Worker::spawn_with(
            healthy_storage,
            Arc::new(NoopT),
            solo_cfg(),
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        std::thread::sleep(Duration::from_millis(50));
        assert!(
            !healthy_worker.init_failed(),
            "init_failed must be false when init succeeded",
        );
        healthy_worker.shutdown();
    }

    // Also still verify the legacy signal: snapshot() returns
    // None because the worker is gone.
    let h = worker.handler();
    let snap = block_on(h.snapshot());
    assert!(
        snap.is_none(),
        "snapshot must be None after silent exit; got {snap:?}",
    );

    // Drop or shutdown joins the (already exited) thread.
    worker.shutdown();
}

/// `term_at` failure during the AppendEntries consistency check
/// propagates `Err` from `handle_append_entries`, the handler
/// drops the reply silently (same shape as the
/// `commit_batch`-failure case). The fallback fires from
/// `WorkerHandle::handle_inbound_append`'s default reply.
///
/// First-call failure path verified here covers the
/// `state.storage.term_at(req.prev_log_index).await?` site at
/// the start of the consistency check.
#[test]
fn term_at_failure_during_consistency_check() {
    let storage = FaultStorage::new(MemStorage::<u16>::new());
    let fail_term = storage.fail_term_at_handle();
    // First (and only) term_at call in this RPC's path will fail.
    fail_term.store(1, Ordering::Relaxed);

    let worker = Worker::spawn_with(
        storage,
        Arc::new(NoopT),
        multi_cfg(),
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    let h = worker.handler();

    let fut = h.handle_inbound_append(
        0xBBBB,
        AppendEntriesReq {
            leader: 0xBBBB,
            term: 5,
            prev_log_index: 0,
            prev_log_term: 0,
            leader_commit: 0,
            entries: vec![],
        },
    );
    let resp = run_with_timeout(fut, Duration::from_millis(200))
        .expect("handle returned");
    assert!(
        !resp.success,
        "follower must report failure when term_at lookup fails",
    );

    // After the fault budget is exhausted, the same RPC succeeds.
    fail_term.store(0, Ordering::Relaxed);
    let resp2 = block_on(h.handle_inbound_append(
        0xBBBB,
        AppendEntriesReq {
            leader: 0xBBBB,
            term: 5,
            prev_log_index: 0,
            prev_log_term: 0,
            leader_commit: 0,
            entries: vec![],
        },
    ));
    assert!(resp2.success, "second call must succeed once term_at faults clear");
    worker.shutdown();
}

// ── Plumbing ───────────────────────────────────────────────────

/// `block_on` with a wall-clock deadline. Returns `None` if the
/// future doesn't resolve in time. Drives the future on a
/// `LocalPool` and steps until either it's ready or the
/// deadline passes — no separate thread, so no `'static` bound.
fn run_with_timeout<F: core::future::Future>(
    fut: F,
    timeout: Duration,
) -> Option<F::Output> {
    use core::pin::pin;
    use core::task::{Context, Poll};
    use futures_executor::LocalPool;
    let mut pool = LocalPool::new();
    let waker = pool.spawner();
    let _ = waker; // suppress unused — LocalPool::run_until_stalled handles waking.
    let mut fut = pin!(fut);
    let deadline = std::time::Instant::now() + timeout;
    loop {
        // Run anything ready, then poll our future once.
        pool.run_until_stalled();
        // Build a noop waker just to poll once outside the pool.
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        if let Poll::Ready(out) = fut.as_mut().poll(&mut cx) {
            return Some(out);
        }
        if std::time::Instant::now() >= deadline {
            return None;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn noop_waker() -> core::task::Waker {
    use core::task::{RawWaker, RawWakerVTable, Waker};
    static VTABLE: RawWakerVTable = RawWakerVTable::new(
        |_| RawWaker::new(core::ptr::null(), &VTABLE),
        |_| {},
        |_| {},
        |_| {},
    );
    let raw = RawWaker::new(core::ptr::null(), &VTABLE);
    unsafe { Waker::from_raw(raw) }
}

// Keep the unused-import quieter when the file is built without
// some of the symbols on certain feature combinations.
#[allow(dead_code)]
fn _unused_check<C: Clock, R: Rng, A: ApplySink>() {}

/// Race regression: many concurrent threads draining a budget
/// of N must observe EXACTLY N "you fail" verdicts in total —
/// no underflow, no double-spend. The CAS loop in
/// `take_fault_budget` is what makes this hold.
#[test]
fn fault_budget_is_race_safe() {
    use std::sync::Arc as StdArc;
    use std::thread;

    const BUDGET: u64 = 100;
    const THREADS: usize = 16;
    const PER_THREAD_CALLS: usize = 200;

    let budget = StdArc::new(AtomicU64::new(BUDGET));
    let total_fails = StdArc::new(AtomicU64::new(0));

    let mut handles = Vec::new();
    for _ in 0..THREADS {
        let b = budget.clone();
        let f = total_fails.clone();
        handles.push(thread::spawn(move || {
            for _ in 0..PER_THREAD_CALLS {
                if take_fault_budget(&b) {
                    f.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }
    for h in handles {
        h.join().unwrap();
    }

    let observed = total_fails.load(Ordering::Relaxed);
    assert_eq!(
        observed, BUDGET,
        "fault budget race: scheduled {BUDGET} faults but {observed} call sites failed",
    );
    // Counter is exhausted: subsequent calls must always pass.
    assert!(!take_fault_budget(&budget));
}
