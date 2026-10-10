//! A store that fails. A worker whose store returns `Err` cannot know what
//! reached the disk, so it stops rather than carry on as if the operation
//! had happened: at boot, `wait_init` reports the failure; later, the
//! worker exits, sends nothing more, and its handles report it stopped.

#![cfg(feature = "std")]

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_executor::block_on;
use vos_raft::{
    ActiveConfigRecord, Envelope, LogEntry, MemStorage, Message, Meta, ProposeError,
    ReadIndexError, Role, StdClock, StdRng, Storage, Transport, Worker, WorkerHandle, WriteBatch,
};

/// A store that fails the next N calls of a method, then delegates.
struct FaultStorage<S> {
    inner: S,
    fail_commit: Arc<AtomicU64>,
    fail_load_meta: Arc<AtomicU64>,
    fail_entries: Arc<AtomicU64>,
}

impl<S> FaultStorage<S> {
    fn new(inner: S) -> Self {
        Self {
            inner,
            fail_commit: Arc::default(),
            fail_load_meta: Arc::default(),
            fail_entries: Arc::default(),
        }
    }
}

#[derive(Debug)]
struct FaultErr;

/// Consume one fault from `budget`: whether this call fails.
fn take(budget: &AtomicU64) -> bool {
    budget
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |left| {
            left.checked_sub(1)
        })
        .is_ok()
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
        self.inner.term_at(index).await.map_err(|_| FaultErr)
    }
    async fn entries(&self, start: u64, end: u64) -> Result<Vec<LogEntry<u16>>, Self::Error> {
        if take(&self.fail_entries) {
            return Err(FaultErr);
        }
        self.inner.entries(start, end).await.map_err(|_| FaultErr)
    }
    async fn read_state(&self) -> Result<Vec<u8>, Self::Error> {
        self.inner.read_state().await.map_err(|_| FaultErr)
    }
    async fn load_meta(&self) -> Result<Meta<u16>, Self::Error> {
        if take(&self.fail_load_meta) {
            return Err(FaultErr);
        }
        self.inner.load_meta().await.map_err(|_| FaultErr)
    }
    async fn active_config(&self) -> Result<Option<ActiveConfigRecord<u16>>, Self::Error> {
        self.inner.active_config().await.map_err(|_| FaultErr)
    }
    async fn commit_batch(&mut self, batch: WriteBatch<u16>) -> Result<(), Self::Error> {
        if take(&self.fail_commit) {
            return Err(FaultErr);
        }
        self.inner.commit_batch(batch).await.map_err(|_| FaultErr)
    }
}

/// Captures what a worker sends.
#[derive(Default)]
struct Capture {
    sent: Mutex<Vec<(u16, Envelope<u16>)>>,
}

impl Transport<u16> for Capture {
    fn send(&self, _from: u16, to: u16, envelope: Envelope<u16>) {
        self.sent.lock().unwrap().push((to, envelope));
    }
}

const ME: u16 = 0xAAAA;
const PEER: u16 = 0xBBBB;

fn solo_cfg() -> vos_raft::Config<u16> {
    let mut c = vos_raft::Config::new(ME, vec![ME], [0u8; 32]);
    c.election_timeout_ms = (15, 30);
    c.heartbeat_interval_ms = 10;
    c
}

fn follower_cfg() -> vos_raft::Config<u16> {
    let mut c = vos_raft::Config::new(ME, vec![ME, PEER, 0xCCCC], [0u8; 32]);
    // Long election window: no spontaneous election.
    c.election_timeout_ms = (60_000, 120_000);
    c.heartbeat_interval_ms = 30_000;
    c
}

fn spawn<S: Storage<u16>>(storage: S, cfg: vos_raft::Config<u16>) -> (Worker<u16>, Arc<Capture>) {
    let capture = Arc::new(Capture::default());
    let worker = Worker::spawn_with(
        storage,
        capture.clone(),
        cfg,
        (),
        StdClock,
        StdRng::from_entropy(),
    );
    (worker, capture)
}

fn wait_until_stopped(handle: &WorkerHandle<u16>) {
    let until = Instant::now() + Duration::from_secs(2);
    while block_on(handle.snapshot()).is_some() {
        assert!(
            Instant::now() < until,
            "the worker kept running after its store failed"
        );
        std::thread::sleep(Duration::from_millis(2));
    }
}

/// A follower whose write of an append fails stops without answering:
/// to the leader it looks like a lost message, which Raft tolerates.
#[test]
fn a_failed_append_write_stops_the_follower_unanswered() {
    let storage = FaultStorage::new(MemStorage::<u16>::new());
    let fail = storage.fail_commit.clone();
    let (worker, capture) = spawn(storage, follower_cfg());
    worker.wait_init().expect("init succeeds");
    let h = worker.handler();
    block_on(h.snapshot()).expect("idle");
    fail.store(1, Ordering::Relaxed);

    h.deliver(
        PEER,
        Envelope::Raft(Message::Append {
            term: 2,
            leader: PEER,
            prev_index: 0,
            prev_term: 0,
            commit: 0,
            round: 1,
            entries: vec![LogEntry::data(1, 2, vec![7])],
        }),
    );
    wait_until_stopped(&h);
    assert!(
        capture.sent.lock().unwrap().is_empty(),
        "a stopped follower answered: {:?}",
        capture.sent.lock().unwrap()
    );
    assert_eq!(worker.role(), Role::Follower);
    worker.shutdown();
}

/// A leader whose write fails stops, and leads nothing afterwards: its
/// role reads follower and every request reports it stopped.
#[test]
fn a_failed_leader_write_stops_the_leader() {
    let storage = FaultStorage::new(MemStorage::<u16>::new());
    let fail = storage.fail_commit.clone();
    let (worker, _) = spawn(storage, solo_cfg());
    worker.wait_init().expect("init succeeds");
    let h = worker.handler();
    let until = Instant::now() + Duration::from_secs(2);
    while block_on(h.read_index()).is_err() {
        assert!(Instant::now() < until, "no leader");
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(worker.role(), Role::Leader);

    fail.store(1, Ordering::Relaxed);
    // The proposal's write fails; whether its caller heard an index
    // first, the entry is not committed.
    let _ = block_on(h.propose(vec![1]));
    wait_until_stopped(&h);
    assert_eq!(worker.role(), Role::Follower);
    assert_eq!(block_on(h.read_index()), Err(ReadIndexError::Stopped));
    assert_eq!(block_on(h.propose(vec![2])), Err(ProposeError::Stopped));
    worker.shutdown();
}

/// A `load_meta` failure at boot is reported by `wait_init`; the worker
/// is gone.
#[test]
fn a_failed_load_meta_fails_initialization() {
    let storage = FaultStorage::new(MemStorage::<u16>::new());
    storage.fail_load_meta.store(1, Ordering::Relaxed);
    let (worker, _) = spawn(storage, solo_cfg());
    assert_eq!(worker.wait_init(), Err(()));
    assert!(block_on(worker.handler().snapshot()).is_none());
    worker.shutdown();

    let (healthy, _) = spawn(FaultStorage::new(MemStorage::<u16>::new()), solo_cfg());
    assert_eq!(healthy.wait_init(), Ok(()));
    healthy.shutdown();
}

/// Reading the log back at boot can fail too; that is an initialization
/// failure as well.
#[test]
fn a_failed_log_load_fails_initialization() {
    let mut inner = MemStorage::<u16>::new();
    block_on(inner.commit_batch(WriteBatch {
        appends: vec![LogEntry::data(1, 1, vec![1]), LogEntry::data(2, 1, vec![2])],
        meta: Some(Meta {
            current_term: 1,
            voted_for: None,
            commit_index: 2,
            snap_last_index: 0,
            snap_last_term: 0,
        }),
        ..WriteBatch::default()
    }))
    .unwrap();
    let storage = FaultStorage::new(inner);
    storage.fail_entries.store(1, Ordering::Relaxed);
    let (worker, _) = spawn(storage, solo_cfg());
    assert_eq!(worker.wait_init(), Err(()));
    worker.shutdown();
}
