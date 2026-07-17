//! Tests written during the May 2026 protocol-correctness audit
//! to pin down findings about edge cases in the worker.
//!
//! Each test names the finding it exercises in its docstring so a
//! future regression points back to the audit notes.

#![cfg(feature = "std")]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_executor::block_on;
use vos_raft::{
    AppendEntriesReq, InstallSnapshotReq, LogEntry, MemStorage, Meta, RequestVoteReq, Role,
    StdClock, StdRng, Storage, Transport, Worker, WriteBatch,
};

// ── Shared storage harness ──────────────────────────────────────
//
// We need to inspect the storage state AFTER the worker has run
// against it. The std-feature `Worker::spawn_with` consumes the
// storage by value, so we wrap MemStorage's data in `Arc<Mutex<…>>`
// and implement `Storage` against the shared inner state. The test
// holds clones of every `Arc` and reads them after `worker.shutdown()`.

#[derive(Default)]
struct StorageInner {
    log: BTreeMap<u64, LogEntry<u16>>,
    state: Vec<u8>,
    meta: Meta<u16>,
    active_config: Option<(Vec<u16>, Option<Vec<u16>>)>,
}

#[derive(Clone)]
struct SharedStorage {
    inner: Arc<Mutex<StorageInner>>,
}

impl SharedStorage {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(StorageInner::default())),
        }
    }

    fn with_inner<R>(&self, f: impl FnOnce(&mut StorageInner) -> R) -> R {
        let mut g = self.inner.lock().unwrap();
        f(&mut g)
    }

    fn read_active_config(&self) -> Option<(Vec<u16>, Option<Vec<u16>>)> {
        self.inner.lock().unwrap().active_config.clone()
    }

    fn read_log_entries(&self) -> BTreeMap<u64, LogEntry<u16>> {
        self.inner.lock().unwrap().log.clone()
    }
}

impl Storage<u16> for SharedStorage {
    type Error = core::convert::Infallible;

    fn last_index(&self) -> u64 {
        let g = self.inner.lock().unwrap();
        g.log
            .keys()
            .next_back()
            .copied()
            .unwrap_or(g.meta.snap_last_index)
    }
    fn last_term(&self) -> u64 {
        let g = self.inner.lock().unwrap();
        g.log
            .values()
            .next_back()
            .map(|e| e.term)
            .unwrap_or(g.meta.snap_last_term)
    }
    fn snap_last_index(&self) -> u64 {
        self.inner.lock().unwrap().meta.snap_last_index
    }
    fn snap_last_term(&self) -> u64 {
        self.inner.lock().unwrap().meta.snap_last_term
    }
    async fn term_at(&self, index: u64) -> Result<Option<u64>, Self::Error> {
        let g = self.inner.lock().unwrap();
        if index == 0 {
            return Ok(Some(0));
        }
        if index < g.meta.snap_last_index {
            return Ok(None);
        }
        if index == g.meta.snap_last_index && g.meta.snap_last_index > 0 {
            return Ok(Some(g.meta.snap_last_term));
        }
        Ok(g.log.get(&index).map(|e| e.term))
    }
    async fn entries(&self, start: u64, end: u64) -> Result<Vec<LogEntry<u16>>, Self::Error> {
        let g = self.inner.lock().unwrap();
        if start > end {
            return Ok(Vec::new());
        }
        let eff = start.max(g.meta.snap_last_index + 1);
        Ok(g.log.range(eff..=end).map(|(_, v)| v.clone()).collect())
    }
    async fn read_state(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(self.inner.lock().unwrap().state.clone())
    }
    async fn load_meta(&self) -> Result<Meta<u16>, Self::Error> {
        Ok(self.inner.lock().unwrap().meta.clone())
    }
    async fn active_config(&self) -> Result<Option<(Vec<u16>, Option<Vec<u16>>)>, Self::Error> {
        Ok(self.inner.lock().unwrap().active_config.clone())
    }
    async fn commit_batch(&mut self, batch: WriteBatch<u16>) -> Result<(), Self::Error> {
        let mut g = self.inner.lock().unwrap();
        if let Some(after) = batch.truncate_after {
            g.log.retain(|k, _| *k <= after);
        }
        if let Some((idx, term)) = batch.compact_to {
            g.log.retain(|k, _| *k > idx);
            g.meta.snap_last_index = idx;
            g.meta.snap_last_term = term;
        }
        for entry in batch.appends {
            g.log.insert(entry.index, entry);
        }
        if let Some(state) = batch.state {
            g.state = state;
        }
        if let Some(meta) = batch.meta {
            g.meta = meta;
        }
        if let Some(cfg) = batch.active_config {
            g.active_config = Some(cfg);
        }
        Ok(())
    }
}

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

// ── Audit Finding #1: persisted active_config goes stale ──────
//
// `recover_active_config` (with `consult_persisted = true`)
// returns `active_config_index = None` for a non-joint persisted
// view, even when the originating `ConfigChange` entry is alive
// in the live log. As a result, a subsequent truncate that drops
// that entry does NOT trigger `truncate_invalidated_cfg`, the
// in-memory `effective_cfg` is left pointing at the persisted
// (now-stale) view, and the persisted row itself is never
// rewritten. On the next reboot the worker again adopts the stale
// view — silently, with no log entry to back it.

/// Pre-condition: the worker boots with a persisted active_config
/// (members = [1,2,3,4]) AND a live-log `ConfigChange` entry at
/// index 1 that matches it. cfg.members is the smaller set
/// [1,2,3].
///
/// Action: a higher-term leader sends AppendEntries that
/// truncates index 1 (the CC entry) and replaces it with a Data
/// entry. The replacement batch contains no ConfigChange.
///
/// Expected: after the truncate, the persisted active_config row
/// must NOT keep claiming [1,2,3,4]. Either:
///   (a) it has been overwritten with the post-truncate view
///       (cfg.members fallback or the new log scan result), or
///   (b) it has been cleared (None / steady cfg.members).
///
/// Observed (pre-fix): persisted row still says [1,2,3,4] —
/// silently stale.
#[test]
fn truncate_dropping_originating_config_change_invalidates_persisted_view() {
    let storage = SharedStorage::new();

    // Pre-populate: persisted view = ([1,2,3,4], None) and a
    // live-log CC entry at idx=1 (term=1) that produced it.
    storage.with_inner(|g| {
        g.active_config = Some((vec![1u16, 2, 3, 4], None));
        g.log
            .insert(1, LogEntry::config_change(1, 1, None, vec![1u16, 2, 3, 4]));
        g.meta = Meta {
            current_term: 1,
            voted_for: None,
            commit_index: 0,
            snap_last_index: 0,
            snap_last_term: 0,
        };
    });

    // Sanity: persisted view round-trips.
    assert_eq!(storage.read_active_config(), Some((vec![1, 2, 3, 4], None)),);

    let storage_handle = storage.clone();

    // Worker boots with cfg.members = [1,2,3] — the static
    // cluster, smaller than the persisted view.
    let mut c = vos_raft::Config::new(1u16, vec![1u16, 2, 3], [0u8; 32]);
    // Long election window so no spontaneous election fires while
    // we drive the truncate.
    c.election_timeout_ms = (60_000, 120_000);
    c.heartbeat_interval_ms = 30_000;
    c.pre_vote = false;
    let worker = Worker::spawn_with(
        storage_handle,
        Arc::new(NoopT),
        c,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    worker.wait_init().expect("init succeeds");

    // Higher-term leader sends AppendEntries that conflicts at
    // index 1 (different term + kind). The follower truncates
    // after 0 and grafts the new Data entry. No new CC in the
    // batch, so the worker shouldn't carry forward [1,2,3,4]
    // unchallenged.
    let h = worker.handler();
    let resp = block_on(h.handle_inbound_append(
        9u16,
        AppendEntriesReq {
            leader: 9u16,
            term: 5,
            prev_log_index: 0,
            prev_log_term: 0,
            leader_commit: 0,
            entries: vec![LogEntry::data(1, 5, vec![0xFF])],
        },
    ));
    assert!(resp.success, "follower must accept the higher-term batch");

    worker.shutdown();

    // Inspect the persisted active_config and the live log.
    let log = storage.read_log_entries();
    assert_eq!(log.len(), 1, "log should have exactly one entry");
    let entry = &log[&1];
    assert_eq!(entry.term, 5, "the entry at idx=1 was replaced (term=5)");
    assert!(
        matches!(entry.kind, vos_raft::EntryKind::Data { .. }),
        "the entry is now Data, not ConfigChange",
    );

    // The bug: persisted active_config row STILL says [1,2,3,4],
    // but no ConfigChange survives in the log. On reboot the
    // worker would adopt this stale view.
    let persisted_after = storage.read_active_config();
    assert!(
        !matches!(persisted_after, Some((ref m, _)) if m == &vec![1u16, 2, 3, 4]),
        "persisted active_config must NOT keep claiming [1,2,3,4] after the \
         CC entry that produced it was truncated; got {persisted_after:?}",
    );
}

// ── Audit Finding #2: out-of-order AppendEntriesResp regresses match_index ──
//
// `handle_append_response` does
//     leader.match_index.insert(from, resp.match_index);
//     leader.next_index.insert(from, resp.match_index + 1);
// unconditionally — no max() clamp. If two AppendEntries are
// in flight to the same peer (heartbeat tick N then N+1) and
// their replies arrive in reverse order, the SECOND reply's
// LOWER `match_index` will overwrite the first reply's higher
// value. Per Raft §5.3 the leader's matchIndex is monotonic —
// "the highest log entry known to be replicated" — so this is a
// monotonicity bug.
//
// Observable consequence: the lagged match_index slows
// subsequent commit_index advancement and `try_compact`
// (compaction floor regresses too). It does NOT roll commit_index
// backwards (try_advance_commit_index only advances) but it
// stalls progress whenever a stale ack arrives after a fresh
// one.
//
// We exercise this directly by feeding the worker two
// AppendEntries from a controlled "follower" identity, where the
// leader's outbound replies are mediated by a transport we
// orchestrate. Constructing a full multi-node leader with reply
// reordering is heavy; instead we drive the public state machine
// from the receiver side and check the symmetric behavior on the
// follower's side: a stale lower-index AppendEntries from the
// same leader should not roll back the follower's view of its
// `last_log_index`.
//
// (The match_index monotonicity invariant on the leader side is
// not directly observable through the public API; we file it as
// a finding without an automated regression test. See the audit
// notes for the suggested fix in `handle_append_response`.)

/// Stale AppendEntries from the same leader at the same term —
/// containing an OLD prefix of entries the follower has already
/// applied — must not regress the follower's `last_log_index`.
/// The receiver's "already_present" branch should keep the log
/// intact.
///
/// This is the symmetric receive-side check for the leader-side
/// match_index monotonicity finding: even if a stale reply
/// confuses the leader, the follower's log cannot be coerced
/// backward by replaying older AppendEntries.
#[test]
fn stale_append_entries_does_not_regress_follower_log() {
    let storage = MemStorage::<u16>::new();
    let mut c = vos_raft::Config::new(1u16, vec![1u16, 2, 3], [0u8; 32]);
    c.election_timeout_ms = (60_000, 120_000);
    c.heartbeat_interval_ms = 30_000;
    c.pre_vote = false;
    let worker = Worker::spawn_with(
        storage,
        Arc::new(NoopT),
        c,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    let h = worker.handler();

    // Fresh leader at term 5 sends a 3-entry batch.
    let r1 = block_on(h.handle_inbound_append(
        2u16,
        AppendEntriesReq {
            leader: 2u16,
            term: 5,
            prev_log_index: 0,
            prev_log_term: 0,
            leader_commit: 0,
            entries: vec![
                LogEntry::data(1, 5, vec![1]),
                LogEntry::data(2, 5, vec![2]),
                LogEntry::data(3, 5, vec![3]),
            ],
        },
    ));
    assert!(r1.success);
    let snap1 = block_on(h.snapshot()).unwrap();
    assert_eq!(snap1.last_log_index, 3);

    // STALE replay: same leader, same term, but only the first 2
    // entries (a duplicated tick that arrived after the fresh 3).
    // The receiver's already-present scan should treat both as
    // present and not truncate the third entry.
    let r2 = block_on(h.handle_inbound_append(
        2u16,
        AppendEntriesReq {
            leader: 2u16,
            term: 5,
            prev_log_index: 0,
            prev_log_term: 0,
            leader_commit: 0,
            entries: vec![LogEntry::data(1, 5, vec![1]), LogEntry::data(2, 5, vec![2])],
        },
    ));
    assert!(r2.success);
    let snap2 = block_on(h.snapshot()).unwrap();
    assert_eq!(
        snap2.last_log_index, 3,
        "stale shorter AppendEntries must not truncate the live tail",
    );

    worker.shutdown();
}

// ── Audit Finding #3: solo-cluster compact safety ────────────
//
// `try_compact` uses `match_index_majority_floor` rather than
// `commit_index` as the compaction target, with a debug_assert
// that `floor <= commit_index`. The standard leader-promotion
// no-op normally keeps these aligned (the no-op is always at
// `commit_index` once a majority acks). But the no-op gate
// relies on the `commit_batch` of the no-op succeeding. If a
// caller-injected scenario broke that invariant, the
// debug_assert would fire in tests but the release build would
// silently compact past commit_index — a violation of the
// `snap_last_index <= commit_index` invariant.
//
// In normal operation we'd want a regression test that
// _actively_ tries to make the floor > commit_index. The cleanest
// observable property is symmetric: across an end-to-end
// 3-node cluster doing many proposes, snap_last_index never
// exceeds commit_index. We pin that here.

/// In a 3-node cluster where the leader proposes many entries
/// (enough to trigger the auto-compaction hysteresis), every
/// replica's `snap_last_index` must remain ≤ `commit_index` at
/// every observation.
#[test]
fn snap_last_index_never_exceeds_commit_index_in_a_running_cluster() {
    use std::sync::Mutex as StdMutex;
    use vos_raft::{
        AppendEntriesResp, InstallSnapshotResp, PreVoteReq, PreVoteResp, RequestVoteResp,
    };

    type Routes = Arc<StdMutex<BTreeMap<u16, vos_raft::WorkerHandle<u16>>>>;

    struct MockTransport {
        routes: Routes,
    }

    #[derive(Debug)]
    struct E;
    impl core::fmt::Display for E {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "x")
        }
    }
    impl std::error::Error for E {}

    impl Transport<u16> for MockTransport {
        type Error = E;
        async fn send_append(
            &self,
            peer: u16,
            req: AppendEntriesReq<u16>,
        ) -> Result<AppendEntriesResp, E> {
            let h = { self.routes.lock().unwrap().get(&peer).cloned() };
            match h {
                Some(h) => Ok(h.handle_inbound_append(req.leader, req).await),
                None => Err(E),
            }
        }
        async fn send_vote(
            &self,
            peer: u16,
            req: RequestVoteReq<u16>,
        ) -> Result<RequestVoteResp, E> {
            let h = { self.routes.lock().unwrap().get(&peer).cloned() };
            match h {
                Some(h) => Ok(h.handle_inbound_vote(req.candidate, req).await),
                None => Err(E),
            }
        }
        async fn send_prevote(&self, peer: u16, req: PreVoteReq<u16>) -> Result<PreVoteResp, E> {
            let h = { self.routes.lock().unwrap().get(&peer).cloned() };
            match h {
                Some(h) => Ok(h.handle_inbound_prevote(req.candidate, req).await),
                None => Err(E),
            }
        }
        async fn send_install(
            &self,
            peer: u16,
            req: InstallSnapshotReq<u16>,
        ) -> Result<InstallSnapshotResp, E> {
            let h = { self.routes.lock().unwrap().get(&peer).cloned() };
            match h {
                Some(h) => Ok(h.handle_inbound_install(req.leader, req).await),
                None => Err(E),
            }
        }
    }

    let routes: Routes = Arc::new(StdMutex::new(BTreeMap::new()));
    let transport = Arc::new(MockTransport {
        routes: routes.clone(),
    });

    let members = vec![1u16, 2, 3];
    let mut workers = Vec::new();
    for me in members.iter().copied() {
        let storage = MemStorage::<u16>::new();
        let mut c = vos_raft::Config::new(me, members.clone(), [0xC0; 32]);
        c.election_timeout_ms = (30, 80);
        c.heartbeat_interval_ms = 15;
        // Tight hysteresis so compaction fires often within the
        // test window.
        c.compact_hysteresis = 4;
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            c,
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        routes.lock().unwrap().insert(me, worker.handler());
        workers.push(worker);
    }

    // Wait for a leader.
    let until = std::time::Instant::now() + Duration::from_secs(3);
    loop {
        if workers.iter().any(|w| w.role() == Role::Leader) {
            break;
        }
        assert!(std::time::Instant::now() < until, "no leader");
        std::thread::sleep(Duration::from_millis(5));
    }
    let leader_idx = workers
        .iter()
        .position(|w| w.role() == Role::Leader)
        .unwrap();
    let leader_handle = workers[leader_idx].handler();

    // Propose 30 entries — well past hysteresis=4.
    for n in 0..30u8 {
        block_on(leader_handle.propose(vec![n])).expect("propose");
    }

    // Drain progress: wait for every replica to commit the tail.
    // The no-op + 30 proposes = 31 entries. commit_index should
    // reach 31 on every replica.
    let until = std::time::Instant::now() + Duration::from_secs(5);
    loop {
        let all_caught = workers.iter().all(|w| {
            block_on(w.handler().snapshot())
                .map(|s| s.commit_index >= 31)
                .unwrap_or(false)
        });
        if all_caught {
            break;
        }
        assert!(
            std::time::Instant::now() < until,
            "replicas didn't catch up to commit_index >= 31",
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    // Audit the invariant: every replica's snap_last_index must
    // be ≤ commit_index. Sample over a short window during which
    // compaction can fire on the leader.
    let until = std::time::Instant::now() + Duration::from_millis(500);
    while std::time::Instant::now() < until {
        for (i, w) in workers.iter().enumerate() {
            let s = block_on(w.handler().snapshot()).unwrap();
            assert!(
                s.snap_last_index <= s.commit_index,
                "node {i}: snap_last_index ({}) exceeded commit_index ({}) — \
                 compaction violated the invariant",
                s.snap_last_index,
                s.commit_index,
            );
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

// ── Audit Finding #4: removed leader retains stale match_index ──
//
// Re-evaluated during the fix pass: the supposed bug is actually
// a non-issue. `auto_finalize_joint_config` calls
// `rebuild_leader_tracking` on the steady-config transition,
// which `retain`-drops any peer no longer in `effective_cfg`.
// A subsequent `change_membership` that re-adds the same peer
// hits `entry.or_insert(0)` against an absent key and gets a
// fresh `match_index = 0`. No carry-over. No fix required.

// ── Audit Finding #5: PreVote leader-check on fresh boot ──
//
// Considered tightening to also refuse pre-votes while our own
// election timer is still in the future. That deadlocks cluster
// startup: every fresh follower's deadline is in the future, so
// nobody grants the first pre-vote round. Reverted. The
// existing behavior — waive the leader-check when
// `last_heartbeat_received` is `None` — is the right trade-off
// (no leader to protect on a fresh boot, and pre-vote alone
// doesn't bump term or persist vote_for, so there's nothing to
// "protect" against either).

// ── Audit Finding #6: no-op append failure during leader promotion ──
//
// Fixed: `become_leader_no_heartbeat` now persists the no-op
// FIRST and only flips role / installs `current_term_first_index`
// after the storage write succeeds. A `commit_batch` Err leaves
// the worker as Candidate; the next election timer retries.
// Pinned by `no_op_append_failure_keeps_us_out_of_leader_role`
// below.

/// `become_leader_no_heartbeat` must NOT promote to Leader
/// before the no-op `commit_batch` lands. Without this ordering,
/// a transient storage failure leaves the worker in role=Leader
/// without `current_term_first_index` set; `read_index` would
/// then resolve against a possibly prior-term `commit_index`,
/// breaking linearizability (Ongaro §6.4).
///
/// Driven against a solo cluster so self-vote alone wins the
/// election. Inject a `commit_batch` failure on the no-op write,
/// observe the worker stay in non-Leader role through the
/// election attempt.
#[test]
fn no_op_append_failure_keeps_us_out_of_leader_role() {
    use std::sync::atomic::{AtomicU64, Ordering as AO};

    #[derive(Debug)]
    struct E;
    impl core::fmt::Display for E {
        fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
            write!(f, "fail")
        }
    }
    impl std::error::Error for E {}

    struct FailingStorage {
        inner: MemStorage<u16>,
        no_op_fails: Arc<AtomicU64>,
    }
    impl Storage<u16> for FailingStorage {
        type Error = E;
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
            Ok(self.inner.term_at(index).await.unwrap())
        }
        async fn entries(&self, start: u64, end: u64) -> Result<Vec<LogEntry<u16>>, Self::Error> {
            Ok(self.inner.entries(start, end).await.unwrap())
        }
        async fn read_state(&self) -> Result<Vec<u8>, Self::Error> {
            Ok(self.inner.read_state().await.unwrap())
        }
        async fn load_meta(&self) -> Result<Meta<u16>, Self::Error> {
            Ok(self.inner.load_meta().await.unwrap())
        }
        async fn active_config(&self) -> Result<Option<(Vec<u16>, Option<Vec<u16>>)>, Self::Error> {
            Ok(self.inner.active_config().await.unwrap())
        }
        async fn commit_batch(&mut self, batch: WriteBatch<u16>) -> Result<(), Self::Error> {
            let is_no_op = batch.appends.len() == 1
                && batch.appends[0].payload().is_some_and(|p| p.is_empty())
                && batch.compact_to.is_none()
                && batch.truncate_after.is_none()
                && batch.state.is_none();
            if is_no_op
                && self
                    .no_op_fails
                    .fetch_update(AO::Relaxed, AO::Relaxed, |v| {
                        if v > 0 { Some(v - 1) } else { None }
                    })
                    .is_ok()
            {
                return Err(E);
            }
            self.inner.commit_batch(batch).await.map_err(|_| E)
        }
    }

    let no_op_fails = Arc::new(AtomicU64::new(3));
    let storage = FailingStorage {
        inner: MemStorage::<u16>::new(),
        no_op_fails: no_op_fails.clone(),
    };

    let mut c = vos_raft::Config::new(0xAAAA, vec![0xAAAA], [0u8; 32]);
    c.election_timeout_ms = (15, 30);
    c.heartbeat_interval_ms = 50;
    let worker = Worker::spawn_with(
        storage,
        Arc::new(NoopT),
        c,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    worker.wait_init().expect("init succeeds");

    let h = worker.handler();
    // Sample for ~150ms while the no-op is failing. The worker
    // must NOT be Leader during this window — every promotion
    // attempt fails on the no-op append, and the new ordering
    // keeps the role at Candidate (election timer retries).
    let until = std::time::Instant::now() + Duration::from_millis(150);
    while std::time::Instant::now() < until && no_op_fails.load(AO::Relaxed) > 0 {
        let snap = block_on(h.snapshot()).unwrap();
        assert_ne!(
            snap.role,
            Role::Leader,
            "worker promoted to Leader despite the no-op append failing — \
             current_term_first_index would be unset and read_index would \
             leak prior-term state",
        );
        std::thread::sleep(Duration::from_millis(5));
    }

    // Once the budget is exhausted, the next election attempt
    // succeeds — the worker should reach Leader.
    let until = std::time::Instant::now() + Duration::from_secs(2);
    loop {
        let snap = block_on(h.snapshot()).unwrap();
        if snap.role == Role::Leader {
            break;
        }
        assert!(
            std::time::Instant::now() < until,
            "worker never promoted to Leader after no-op fault budget cleared",
        );
        std::thread::sleep(Duration::from_millis(10));
    }

    worker.shutdown();
}

/// `handle_install_snapshot` must persist the current
/// `effective_cfg` alongside the compaction so the on-disk
/// `active_config` row stays in step with the post-install
/// state. Without this, a follower whose snapshot install
/// compacts past the entry that produced its in-memory
/// `effective_cfg` would, on next reboot, scan an empty live
/// log, fall back to `cfg.members`, and silently drop the
/// membership view it had been operating with.
#[test]
fn install_snapshot_persists_effective_cfg_after_compaction() {
    let storage = SharedStorage::new();

    // Pre-populate: log has a ConfigChange{None, [1,2,3]} at
    // idx=5 and a Data entry at idx=6. cfg.members = [1] (a
    // smaller starting set we don't expect to fall back to).
    storage.with_inner(|g| {
        g.log
            .insert(5, LogEntry::config_change(5, 1, None, vec![1u16, 2, 3]));
        g.log.insert(6, LogEntry::data(6, 1, vec![0xAA]));
        g.meta = Meta {
            current_term: 1,
            voted_for: None,
            commit_index: 6,
            snap_last_index: 0,
            snap_last_term: 0,
        };
        // Persisted active_config matches log.
        g.active_config = Some((vec![1u16, 2, 3], None));
    });

    let storage_handle = storage.clone();
    let mut c = vos_raft::Config::new(1u16, vec![1u16], [0u8; 32]);
    c.election_timeout_ms = (60_000, 120_000);
    c.heartbeat_interval_ms = 30_000;
    c.pre_vote = false;
    let worker = Worker::spawn_with(
        storage_handle,
        Arc::new(NoopT),
        c,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    worker.wait_init().expect("init succeeds");
    let h = worker.handler();

    // Leader installs a snapshot whose last_included_index = 10
    // — past the ConfigChange at idx=5. The follower's compacted
    // log loses both entries; only the snapshot row remains.
    let resp = block_on(h.handle_inbound_install(
        9u16,
        InstallSnapshotReq {
            leader: 9,
            term: 5,
            last_included_index: 10,
            last_included_term: 5,
            offset: 0,
            done: true,
            data: vec![0xCC; 8],
            members: Vec::new(),
            joint_old: None,
        },
    ));
    assert_eq!(resp.bytes_received, 8);

    worker.shutdown();

    // The post-install persisted active_config must still hold
    // the post-state membership view ([1,2,3]) — NOT regress
    // to the pre-install state, and NOT silently revert to
    // cfg.members ([1]). Either would force a stale view on
    // reboot.
    let persisted = storage.read_active_config();
    assert_eq!(
        persisted,
        Some((vec![1u16, 2, 3], None)),
        "persisted active_config must reflect the post-install \
         effective_cfg, not vanish or revert to cfg.members; got {persisted:?}",
    );

    // Sanity: the log no longer contains the originating CC.
    let log = storage.read_log_entries();
    assert!(
        log.is_empty(),
        "log entries ≤ last_included_index should be compacted away; got {log:?}",
    );
}

/// A fresh follower whose first activity is an `InstallSnapshot`
/// at a high index has no log to scan and no useful prior
/// `effective_cfg` — it must learn the cluster's current
/// membership from the leader-supplied `members` field on the
/// install RPC. Without that path, the follower would keep its
/// static `cfg.members` and silently disagree with the rest of
/// the cluster on quorum / heartbeat targets.
#[test]
fn install_snapshot_adopts_leader_supplied_membership_on_fresh_follower() {
    let storage = SharedStorage::new();
    let storage_handle = storage.clone();

    // cfg.members is a SINGLE-NODE set; the live cluster (per
    // the leader's view) is 3-node. We expect the follower to
    // adopt [1,2,3] from the install RPC, not stay on [42].
    let mut c = vos_raft::Config::new(42u16, vec![42u16], [0u8; 32]);
    c.election_timeout_ms = (60_000, 120_000);
    c.heartbeat_interval_ms = 30_000;
    c.pre_vote = false;
    let worker = Worker::spawn_with(
        storage_handle,
        Arc::new(NoopT),
        c,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    worker.wait_init().expect("init succeeds");
    let h = worker.handler();

    let resp = block_on(h.handle_inbound_install(
        1u16,
        InstallSnapshotReq {
            leader: 1u16,
            term: 7,
            last_included_index: 100,
            last_included_term: 6,
            offset: 0,
            done: true,
            data: vec![0xAB; 16],
            members: vec![1u16, 2, 3],
            joint_old: None,
        },
    ));
    assert_eq!(resp.bytes_received, 16);

    worker.shutdown();

    let persisted = storage.read_active_config();
    assert_eq!(
        persisted,
        Some((vec![1u16, 2, 3], None)),
        "follower must adopt leader-supplied membership, not silently \
         retain cfg.members; got {persisted:?}",
    );
}
