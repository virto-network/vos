//! Edge cases of the worker's persistence: membership views across
//! truncation and snapshot installation, terms across restarts, and
//! interrupted snapshot streams. A store that fails is in
//! `fault_injection.rs`.

#![cfg(feature = "std")]

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures_executor::block_on;
use vos_raft::{
    ActiveConfigRecord, AppendResult, Envelope, InstallSnapshotReq, InstallSnapshotResp, LogEntry,
    MemStorage, Message, Meta, Role, StdClock, StdRng, Storage, Transport, Worker, WorkerHandle,
    WriteBatch,
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
    active_config: Option<ActiveConfigRecord<u16>>,
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

    fn read_active_config(&self) -> Option<ActiveConfigRecord<u16>> {
        self.inner.lock().unwrap().active_config.clone()
    }

    fn read_log_entries(&self) -> BTreeMap<u64, LogEntry<u16>> {
        self.inner.lock().unwrap().log.clone()
    }

    fn read_meta(&self) -> Meta<u16> {
        self.inner.lock().unwrap().meta.clone()
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
    async fn active_config(&self) -> Result<Option<ActiveConfigRecord<u16>>, Self::Error> {
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
            assert!(
                meta.snap_last_index >= g.meta.snap_last_index,
                "a write moved the snapshot pointer back: {} -> {}",
                g.meta.snap_last_index,
                meta.snap_last_index
            );
            g.meta = meta;
        }
        if let Some(cfg) = batch.active_config {
            g.active_config = Some(cfg);
        }
        Ok(())
    }
}

/// Captures what workers send, so a test can play their peers.
#[derive(Default)]
struct Capture {
    sent: Mutex<Vec<(u16, Envelope<u16>)>>,
}

impl Transport<u16> for Capture {
    fn send(&self, _from: u16, to: u16, envelope: Envelope<u16>) {
        self.sent.lock().unwrap().push((to, envelope));
    }
}

impl Capture {
    fn take(&self, to: u16) -> Vec<Envelope<u16>> {
        let mut sent = self.sent.lock().unwrap();
        let (theirs, rest): (Vec<_>, Vec<_>) = sent.drain(..).partition(|(at, _)| *at == to);
        *sent = rest;
        theirs.into_iter().map(|(_, envelope)| envelope).collect()
    }
}

/// Deliver `envelope` from `from`, wait until it is handled, and return
/// what the worker sent back to `from`.
fn ask(
    handle: &WorkerHandle<u16>,
    capture: &Capture,
    from: u16,
    envelope: Envelope<u16>,
) -> Vec<Envelope<u16>> {
    handle.deliver(from, envelope);
    block_on(handle.snapshot()).expect("worker alive");
    capture.take(from)
}

fn heartbeat(term: u64, leader: u16) -> Envelope<u16> {
    Envelope::Raft(Message::Append {
        term,
        leader,
        prev_index: 0,
        prev_term: 0,
        commit: 0,
        round: 1,
        entries: vec![],
    })
}

/// A snapshot chunk from `leader`, after the leader's heartbeat at the
/// chunk's term (only the leader a replica follows may install one): the
/// acknowledgement.
fn install(
    handle: &WorkerHandle<u16>,
    capture: &Capture,
    chunk: InstallSnapshotReq<u16>,
) -> InstallSnapshotResp {
    let leader = chunk.leader;
    ask(handle, capture, leader, heartbeat(chunk.term, leader));
    ack(&ask(
        handle,
        capture,
        leader,
        Envelope::SnapshotChunk(chunk),
    ))
}

fn ack(answers: &[Envelope<u16>]) -> InstallSnapshotResp {
    answers
        .iter()
        .find_map(|envelope| match envelope {
            Envelope::SnapshotAck(ack) => Some(*ack),
            _ => None,
        })
        .expect("a snapshot acknowledgement")
}

fn matched(answers: &[Envelope<u16>]) -> Option<u64> {
    answers
        .iter()
        .filter_map(|envelope| match envelope {
            Envelope::Raft(Message::AppendAnswer {
                result: AppendResult::Matched { matched },
                ..
            }) => Some(*matched),
            _ => None,
        })
        .max()
}

fn spawn<S: Storage<u16>>(
    storage: S,
    config: vos_raft::Config<u16>,
) -> (Worker<u16>, Arc<Capture>) {
    let capture = Arc::new(Capture::default());
    let worker = Worker::spawn_with(
        storage,
        capture.clone(),
        config,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    (worker, capture)
}

fn snapshot_test_config(me: u16) -> vos_raft::Config<u16> {
    let mut config = vos_raft::Config::new(me, vec![me, 9], [0u8; 32]);
    config.election_timeout_ms = (60_000, 120_000);
    config.heartbeat_interval_ms = 30_000;
    config.pre_vote = false;
    config
}

/// A snapshot chunk never moves a replica's term: only protocol messages
/// do, and an answer at a new term waits for that term to be durable. A
/// chunk at a higher term is refused until the leader's heartbeat
/// establishes the term, which is then durable across a restart.
#[test]
fn a_chunk_at_a_higher_term_waits_for_the_leaders_heartbeat() {
    let storage = SharedStorage::new();
    storage.with_inner(|inner| {
        inner.meta.current_term = 3;
        inner.meta.voted_for = Some(7);
    });

    let (worker, capture) = spawn(storage.clone(), snapshot_test_config(1));
    worker.wait_init().expect("first worker initializes");
    let chunk = || InstallSnapshotReq {
        leader: 9,
        term: 7,
        last_included_index: 20,
        last_included_term: 6,
        offset: 0,
        done: false,
        data: vec![0xA5; 8],
        members: Vec::new(),
        joint_old: None,
        active_config_index: None,
    };
    let h = worker.handler();
    let refused = ack(&ask(&h, &capture, 9, Envelope::SnapshotChunk(chunk())));
    assert_eq!(refused.bytes_received, 0, "no leader at term 7 yet");
    assert_eq!(storage.read_meta().current_term, 3, "a chunk moves no term");

    ask(&h, &capture, 9, heartbeat(7, 9));
    let accepted = ack(&ask(&h, &capture, 9, Envelope::SnapshotChunk(chunk())));
    assert_eq!(accepted.term, 7);
    assert_eq!(accepted.bytes_received, 8);
    worker.shutdown();

    let persisted = storage.read_meta();
    assert_eq!(persisted.current_term, 7);
    assert_eq!(persisted.voted_for, None);

    let (reopened, _) = spawn(storage, snapshot_test_config(1));
    reopened.wait_init().expect("reopened worker initializes");
    assert_eq!(
        block_on(reopened.handler().snapshot())
            .unwrap()
            .current_term,
        7
    );
    reopened.shutdown();
}

/// Losing the acknowledgement of the final chunk must not strand the
/// leader. An exact retry of a snapshot already installed is acknowledged
/// with the end of that chunk, so the leader can mark the install complete.
#[test]
fn installed_snapshot_retry_recovers_a_lost_final_response() {
    let (worker, capture) = spawn(SharedStorage::new(), snapshot_test_config(1));
    worker.wait_init().expect("worker initializes");
    let h = worker.handler();
    let request = || InstallSnapshotReq {
        leader: 9,
        term: 4,
        last_included_index: 20,
        last_included_term: 3,
        offset: 8,
        done: true,
        data: vec![0x5A; 8],
        members: vec![1, 9],
        joint_old: None,
        active_config_index: Some(20),
    };
    let first = install(
        &h,
        &capture,
        InstallSnapshotReq {
            done: false,
            offset: 0,
            data: vec![0xA5; 8],
            members: Vec::new(),
            active_config_index: None,
            ..request()
        },
    );
    assert_eq!(first.bytes_received, 8);
    let lost = ack(&ask(&h, &capture, 9, Envelope::SnapshotChunk(request())));
    assert_eq!(lost.bytes_received, 16);
    // That acknowledgement is lost; the leader's exact retry is covered.
    let recovered = ack(&ask(&h, &capture, 9, Envelope::SnapshotChunk(request())));
    assert_eq!(recovered.term, 4);
    assert_eq!(recovered.bytes_received, 16);
    worker.shutdown();
}

/// Partial snapshot bytes are volatile. After a follower restart, a
/// later-offset chunk is acknowledged with zero, so the leader rewinds and
/// restarts the stream from the beginning.
#[test]
fn snapshot_stream_requests_rewind_after_midstream_restart() {
    let storage = SharedStorage::new();
    let (worker, capture) = spawn(storage.clone(), snapshot_test_config(1));
    worker.wait_init().expect("first worker initializes");
    let first = install(
        &worker.handler(),
        &capture,
        InstallSnapshotReq {
            leader: 9,
            term: 4,
            last_included_index: 20,
            last_included_term: 3,
            offset: 0,
            done: false,
            data: vec![0xA5; 8],
            members: Vec::new(),
            joint_old: None,
            active_config_index: None,
        },
    );
    assert_eq!(first.bytes_received, 8);
    worker.shutdown();

    let (reopened, capture) = spawn(storage, snapshot_test_config(1));
    reopened.wait_init().expect("reopened worker initializes");
    let rewind = install(
        &reopened.handler(),
        &capture,
        InstallSnapshotReq {
            leader: 9,
            term: 4,
            last_included_index: 20,
            last_included_term: 3,
            offset: 8,
            done: true,
            data: vec![0x5A; 8],
            members: vec![1, 9],
            joint_old: None,
            active_config_index: Some(20),
        },
    );
    assert_eq!(rewind.bytes_received, 0);
    assert_eq!(
        block_on(reopened.handler().snapshot())
            .unwrap()
            .snap_last_index,
        0
    );
    reopened.shutdown();
}

// ── Membership views and truncation ─────────────────────────────

/// A persisted membership view backed by a live-log `ConfigChange`
/// must not outlive that entry. The worker boots with the view
/// [1,2,3,4] from the entry at index 1 (cfg.members is [1,2,3]); a
/// higher-term leader replaces index 1 with a Data entry. Afterwards
/// the persisted row must no longer claim [1,2,3,4]: on the next boot
/// it would be adopted with no log entry to back it.
#[test]
fn truncate_dropping_originating_config_change_invalidates_persisted_view() {
    let storage = SharedStorage::new();

    // Pre-populate: persisted view = ([1,2,3,4], None) and a
    // live-log CC entry at idx=1 (term=1) that produced it.
    storage.with_inner(|g| {
        g.active_config = Some(ActiveConfigRecord {
            log_index: Some(1),
            current: vec![1u16, 2, 3, 4],
            joint_old: None,
        });
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
    assert_eq!(
        storage.read_active_config(),
        Some(ActiveConfigRecord {
            log_index: Some(1),
            current: vec![1, 2, 3, 4],
            joint_old: None,
        }),
    );

    let storage_handle = storage.clone();

    // Worker boots with cfg.members = [1,2,3] — the static
    // cluster, smaller than the persisted view.
    let mut c = vos_raft::Config::new(1u16, vec![1u16, 2, 3], [0u8; 32]);
    // Long election window so no spontaneous election fires while
    // we drive the truncate.
    c.election_timeout_ms = (60_000, 120_000);
    c.heartbeat_interval_ms = 30_000;
    c.pre_vote = false;
    let (worker, capture) = spawn(storage_handle, c);
    worker.wait_init().expect("init succeeds");

    // Higher-term leader sends AppendEntries that conflicts at
    // index 1 (different term + kind). The follower truncates
    // after 0 and grafts the new Data entry. No new CC in the
    // batch, so the worker shouldn't carry forward [1,2,3,4]
    // unchallenged.
    let h = worker.handler();
    let answers = ask(
        &h,
        &capture,
        2,
        Envelope::Raft(Message::Append {
            term: 5,
            leader: 2,
            prev_index: 0,
            prev_term: 0,
            commit: 0,
            round: 1,
            entries: vec![LogEntry::data(1, 5, vec![0xFF])],
        }),
    );
    assert_eq!(
        matched(&answers),
        Some(1),
        "follower must accept the higher-term batch"
    );

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
        !matches!(persisted_after, Some(ref record) if record.current == vec![1u16, 2, 3, 4]),
        "persisted active_config must NOT keep claiming [1,2,3,4] after the \
         CC entry that produced it was truncated; got {persisted_after:?}",
    );
}

// ── Replayed appends ────────────────────────────────────────────

/// A stale append from the current leader, carrying a prefix of
/// entries the follower already holds (a duplicate that arrived after
/// a longer one), must not truncate the follower's log.
#[test]
fn stale_append_entries_does_not_regress_follower_log() {
    let mut c = vos_raft::Config::new(1u16, vec![1u16, 2, 3], [0u8; 32]);
    c.election_timeout_ms = (60_000, 120_000);
    c.heartbeat_interval_ms = 30_000;
    c.pre_vote = false;
    let (worker, capture) = spawn(MemStorage::<u16>::new(), c);
    let h = worker.handler();
    let append = |entries: Vec<LogEntry<u16>>| {
        Envelope::Raft(Message::Append {
            term: 5,
            leader: 2,
            prev_index: 0,
            prev_term: 0,
            commit: 0,
            round: 1,
            entries,
        })
    };

    // Fresh leader at term 5 sends a 3-entry batch.
    let first = ask(
        &h,
        &capture,
        2,
        append(vec![
            LogEntry::data(1, 5, vec![1]),
            LogEntry::data(2, 5, vec![2]),
            LogEntry::data(3, 5, vec![3]),
        ]),
    );
    assert_eq!(matched(&first), Some(3));
    assert_eq!(block_on(h.snapshot()).unwrap().last_log_index, 3);

    // STALE replay: same leader, same term, but only the first 2
    // entries (a duplicated tick that arrived after the fresh 3).
    // Both are already present; the third must survive.
    let second = ask(
        &h,
        &capture,
        2,
        append(vec![
            LogEntry::data(1, 5, vec![1]),
            LogEntry::data(2, 5, vec![2]),
        ]),
    );
    assert!(matched(&second).is_some());
    assert_eq!(
        block_on(h.snapshot()).unwrap().last_log_index,
        3,
        "stale shorter AppendEntries must not truncate the live tail",
    );

    worker.shutdown();
}

// ── Compaction ──────────────────────────────────────────────────

/// In a 3-node cluster where the leader proposes many entries
/// (enough to trigger compaction often), every replica's
/// `snap_last_index` must remain ≤ `commit_index` at every
/// observation.
#[test]
fn snap_last_index_never_exceeds_commit_index_in_a_running_cluster() {
    /// Routes each message to its addressee's worker.
    #[derive(Default)]
    struct Routes(Mutex<BTreeMap<u16, WorkerHandle<u16>>>);

    impl Transport<u16> for Routes {
        fn send(&self, from: u16, to: u16, envelope: Envelope<u16>) {
            let handle = self.0.lock().unwrap().get(&to).cloned();
            if let Some(handle) = handle {
                handle.deliver(from, envelope);
            }
        }
    }

    let transport = Arc::new(Routes::default());

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
        transport.0.lock().unwrap().insert(me, worker.handler());
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

/// Installing a snapshot persists the membership view in effect
/// alongside the compaction, so the on-disk `active_config` row stays
/// in step. Otherwise a follower whose install compacts past the entry
/// that produced its view would, on the next boot, scan an empty live
/// log, fall back to `cfg.members`, and silently drop that view.
#[test]
fn install_snapshot_persists_the_membership_view_after_compaction() {
    let storage = SharedStorage::new();

    // Pre-populate: a snapshot through idx=4, then a
    // ConfigChange{None, [1,2,3]} at idx=5 and a Data entry at
    // idx=6. cfg.members = [1] (a smaller starting set we don't
    // expect to fall back to).
    storage.with_inner(|g| {
        g.log
            .insert(5, LogEntry::config_change(5, 1, None, vec![1u16, 2, 3]));
        g.log.insert(6, LogEntry::data(6, 1, vec![0xAA]));
        g.meta = Meta {
            current_term: 1,
            voted_for: None,
            commit_index: 6,
            snap_last_index: 4,
            snap_last_term: 1,
        };
        // Persisted active_config matches log.
        g.active_config = Some(ActiveConfigRecord {
            log_index: Some(5),
            current: vec![1u16, 2, 3],
            joint_old: None,
        });
    });

    let storage_handle = storage.clone();
    let mut c = vos_raft::Config::new(1u16, vec![1u16], [0u8; 32]);
    c.election_timeout_ms = (60_000, 120_000);
    c.heartbeat_interval_ms = 30_000;
    c.pre_vote = false;
    let (worker, capture) = spawn(storage_handle, c);
    worker.wait_init().expect("init succeeds");
    let h = worker.handler();

    // Leader installs a snapshot whose last_included_index = 10
    // — past the ConfigChange at idx=5. The follower's compacted
    // log loses both entries; only the snapshot row remains.
    let resp = install(
        &h,
        &capture,
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
            active_config_index: None,
        },
    );
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
        Some(ActiveConfigRecord {
            log_index: Some(5),
            current: vec![1u16, 2, 3],
            joint_old: None,
        }),
        "persisted active_config must reflect the post-install \
         membership view, not vanish or revert to cfg.members; got {persisted:?}",
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
/// membership view — it must learn the cluster's current
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
    let (worker, capture) = spawn(storage_handle, c);
    worker.wait_init().expect("init succeeds");
    let h = worker.handler();

    let resp = install(
        &h,
        &capture,
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
            active_config_index: Some(37),
        },
    );
    assert_eq!(resp.bytes_received, 16);

    worker.shutdown();

    let persisted = storage.read_active_config();
    assert_eq!(
        persisted,
        Some(ActiveConfigRecord {
            log_index: Some(37),
            current: vec![1u16, 2, 3],
            joint_old: None,
        }),
        "follower must adopt leader-supplied membership, not silently \
         retain cfg.members; got {persisted:?}",
    );
}

/// Installing a state-only snapshot may move the commit boundary beyond a
/// locally speculative configuration. That boundary movement must not turn
/// the old configuration index into committed membership evidence.
#[test]
fn snapshot_without_membership_clears_speculative_local_provenance() {
    let storage = SharedStorage::new();
    storage.with_inner(|inner| {
        inner.meta = Meta {
            current_term: 3,
            voted_for: None,
            commit_index: 2,
            snap_last_index: 0,
            snap_last_term: 0,
        };
        for index in 1..5 {
            inner
                .log
                .insert(index, LogEntry::data(index, 3, vec![index as u8]));
        }
        inner.log.insert(
            5,
            LogEntry::config_change(5, 3, Some(vec![9]), vec![1u16, 9]),
        );
        inner.active_config = Some(ActiveConfigRecord {
            log_index: Some(5),
            current: vec![1u16, 9],
            joint_old: Some(vec![9]),
        });
    });

    let (worker, capture) = spawn(storage.clone(), snapshot_test_config(1));
    worker.wait_init().expect("worker initializes");
    let before = block_on(worker.handler().snapshot()).unwrap();
    assert_eq!(before.active_config_index, Some(5));
    assert_eq!(before.commit_index, 2);

    let response = install(
        &worker.handler(),
        &capture,
        InstallSnapshotReq {
            leader: 9,
            term: 4,
            last_included_index: 10,
            last_included_term: 3,
            offset: 0,
            done: true,
            data: vec![0xCD; 16],
            members: Vec::new(),
            joint_old: None,
            active_config_index: None,
        },
    );
    assert_eq!(response.bytes_received, 16);
    worker.shutdown();

    assert_eq!(storage.read_meta().commit_index, 10);
    assert_eq!(
        storage.read_active_config(),
        Some(ActiveConfigRecord {
            log_index: None,
            current: vec![1u16, 9],
            joint_old: Some(vec![9]),
        }),
        "snapshot installation must preserve the membership view without \
         fabricating committed provenance",
    );
}

/// A crash right after a snapshot switch leaves the snapshot with its
/// membership record and commit, never the old ones: they are written in
/// the switch's own batch. Otherwise a replica could restart with the
/// snapshot's state but a membership the group has left, and count a
/// quorum of the wrong members.
#[test]
fn a_crash_after_a_snapshot_switch_keeps_its_membership() {
    /// Refuses every write after the switch, as if the node crashed.
    struct CrashAfterSwitch {
        inner: SharedStorage,
        switched: bool,
    }

    #[derive(Debug)]
    struct Crashed;

    impl Storage<u16> for CrashAfterSwitch {
        type Error = Crashed;
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
        async fn active_config(&self) -> Result<Option<ActiveConfigRecord<u16>>, Self::Error> {
            Ok(self.inner.active_config().await.unwrap())
        }
        async fn commit_batch(&mut self, batch: WriteBatch<u16>) -> Result<(), Self::Error> {
            if self.switched {
                return Err(Crashed);
            }
            self.switched = batch.state.is_some();
            self.inner.commit_batch(batch).await.unwrap();
            Ok(())
        }
    }

    let storage = SharedStorage::new();
    storage.with_inner(|inner| {
        inner.meta.current_term = 3;
        inner.active_config = Some(ActiveConfigRecord {
            log_index: Some(2),
            current: vec![1u16, 2, 9],
            joint_old: None,
        });
    });
    let (worker, capture) = spawn(
        CrashAfterSwitch {
            inner: storage.clone(),
            switched: false,
        },
        snapshot_test_config(1),
    );
    worker.wait_init().expect("worker initializes");
    let h = worker.handler();
    ask(&h, &capture, 9, heartbeat(4, 9));
    h.deliver(
        9,
        Envelope::SnapshotChunk(InstallSnapshotReq {
            leader: 9,
            term: 4,
            last_included_index: 10,
            last_included_term: 4,
            offset: 0,
            done: true,
            data: vec![0xEE; 8],
            members: vec![1, 9],
            joint_old: None,
            active_config_index: Some(8),
        }),
    );
    let until = std::time::Instant::now() + Duration::from_secs(2);
    while block_on(h.snapshot()).is_some() {
        assert!(
            std::time::Instant::now() < until,
            "the write after the switch went through"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
    worker.shutdown();

    let meta = storage.read_meta();
    assert_eq!((meta.snap_last_index, meta.snap_last_term), (10, 4));
    assert!(meta.commit_index >= 10, "{meta:?}");
    assert_eq!(
        storage.read_active_config(),
        Some(ActiveConfigRecord {
            log_index: Some(8),
            current: vec![1, 9],
            joint_old: None,
        })
    );
}

/// Compaction moves the store's snapshot pointer, and no later write moves
/// it back: a replica that compacted while it wrote restarts from a log
/// that starts right after its snapshot.
#[test]
fn compaction_survives_a_restart() {
    let storage = SharedStorage::new();
    let config = || {
        let mut config = vos_raft::Config::new(1u16, vec![1u16], [0u8; 32]);
        config.election_timeout_ms = (10, 20);
        config.heartbeat_interval_ms = 5;
        config.compact_hysteresis = 1;
        config
    };
    let (worker, _) = spawn(storage.clone(), config());
    worker.wait_init().expect("init");
    let h = worker.handler();
    let until = std::time::Instant::now() + Duration::from_secs(2);
    while block_on(h.read_index()).is_err() {
        assert!(std::time::Instant::now() < until, "no leader");
        std::thread::sleep(Duration::from_millis(2));
    }
    for n in 0..40u8 {
        block_on(h.propose(vec![n])).expect("propose");
    }
    let until = std::time::Instant::now() + Duration::from_secs(2);
    while block_on(h.snapshot()).unwrap().commit_index < 41 {
        assert!(std::time::Instant::now() < until, "not committed");
        std::thread::sleep(Duration::from_millis(2));
    }
    worker.shutdown();

    let meta = storage.read_meta();
    assert!(meta.snap_last_index > 0, "compacted: {meta:?}");
    let log = storage.read_log_entries();
    assert_eq!(
        log.keys().next().copied(),
        Some(meta.snap_last_index + 1).filter(|_| !log.is_empty()),
        "the log starts right after the snapshot: {meta:?}, {:?}",
        log.keys().collect::<Vec<_>>()
    );
    let (reopened, _) = spawn(storage, config());
    reopened.wait_init().expect("reopened");
    let status = block_on(reopened.handler().snapshot()).expect("alive");
    assert!(status.last_log_index >= 41, "{status:?}");
    reopened.shutdown();
}
