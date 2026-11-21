use std::sync::atomic::AtomicBool;

use super::*;
use crate::NoHooks;

const A: AgentId = AgentId(1);

fn writer(dir: &std::path::Path) -> StorageThread {
    StorageThread::spawn(Fjall::open(dir).unwrap(), Arc::new(NoHooks))
}

fn apply(index: u64) -> Change {
    apply_at(0, index)
}

fn apply_at(epoch: u8, index: u64) -> Change {
    Change::Apply {
        agent: A,
        epoch,
        index,
        writes: Vec::new(),
    }
}

fn compact(through: u64) -> Change {
    Change::Compact {
        agent: A,
        through,
        term: 1,
        membership: None,
    }
}

fn hard(term: u64, sync: bool) -> Change {
    Change::Hard {
        agent: A,
        hard: HardState {
            term,
            vote: None,
            commit: 0,
        },
        sync,
    }
}

#[test]
fn the_durably_applied_index_moves_only_with_a_synced_flush() {
    let dir = tempfile::tempdir().unwrap();
    let writer = writer(dir.path());
    smol::block_on(writer.commit((1..=5).map(apply).collect())).unwrap();
    smol::block_on(writer.commit(vec![hard(1, false)])).unwrap();
    assert_eq!(
        writer.durably_applied(A),
        0,
        "buffered writes are not durable"
    );
    smol::block_on(writer.commit(vec![hard(2, true)])).unwrap();
    assert_eq!(
        writer.durably_applied(A),
        5,
        "a synced flush covers what came before"
    );
    writer.recovered(AgentId(2), 9);
    assert_eq!(writer.durably_applied(AgentId(2)), 9);
}

/// Fails the next commit, as a store fault would, then lets the rest
/// through.
struct FailOnce(AtomicBool);

impl Hooks for FailOnce {
    fn fail_commit(&self) -> bool {
        self.0.swap(false, Ordering::Relaxed)
    }
}

#[test]
fn applies_of_a_failed_batch_never_count_as_durable() {
    let dir = tempfile::tempdir().unwrap();
    let writer = StorageThread::spawn(
        Fjall::open(dir.path()).unwrap(),
        Arc::new(FailOnce(AtomicBool::new(true))),
    );
    assert!(smol::block_on(writer.commit(vec![apply(5)])).is_err());
    assert_eq!(writer.durably_applied(A), 0);
}

/// Fails the sync of the next synced flush once it is written, as a
/// failed fsync does.
struct FailSyncOnce(AtomicBool);

impl Hooks for FailSyncOnce {
    fn fail_sync(&self) -> bool {
        self.0.swap(false, Ordering::Relaxed)
    }
}

/// After a flush fails, written or not, the writer writes nothing more:
/// its view of the agents' rows may be wrong, so a later commit it
/// checks against that view could destroy what the failed one wrote.
#[test]
fn a_failed_flush_stops_the_writer_for_good() {
    let dir = tempfile::tempdir().unwrap();
    let writer = StorageThread::spawn(
        Fjall::open(dir.path()).unwrap(),
        Arc::new(FailSyncOnce(AtomicBool::new(true))),
    );
    assert!(!writer.failed());
    assert!(smol::block_on(writer.commit(vec![hard(1, true)])).is_err());
    assert!(writer.failed());
    assert!(smol::block_on(writer.commit(vec![hard(2, true)])).is_err());
    assert!(smol::block_on(writer.commit(vec![apply(1)])).is_err());
    drop(writer);
    let store = Fjall::open(dir.path()).unwrap();
    assert_eq!(
        store.raft(A).unwrap().hard.term,
        1,
        "the failed sync's write reached the store; nothing after it did"
    );
}

#[test]
fn compaction_past_the_durably_applied_index_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let writer = writer(dir.path());
    smol::block_on(writer.commit((1..=5).map(apply).collect())).unwrap();
    assert!(smol::block_on(writer.commit(vec![compact(3)])).is_err());
    smol::block_on(writer.commit(vec![hard(1, true)])).unwrap();
    smol::block_on(writer.commit(vec![compact(3)])).unwrap();
    assert!(smol::block_on(writer.commit(vec![compact(6)])).is_err());
}

#[test]
fn stale_applies_stagings_and_switches_are_refused() {
    let dir = tempfile::tempdir().unwrap();
    let writer = writer(dir.path());
    let commit = |change| smol::block_on(writer.commit(vec![change]));
    let switch = |epoch, index| Change::Switch {
        agent: A,
        switch: Switch {
            epoch,
            index,
            term: 1,
            hard: HardState::default(),
            membership: Membership::default(),
            log_start_membership: None,
            truncate_after: None,
        },
    };
    commit(apply_at(0, 1)).unwrap();
    assert!(
        commit(apply_at(0, 1)).is_err(),
        "not past the applied index"
    );
    assert!(commit(apply_at(0, 3)).is_err(), "not the next index");
    let stage = |epoch| Change::Stage {
        agent: A,
        epoch,
        first: true,
        rows: Vec::new(),
    };
    assert!(commit(stage(0)).is_err(), "the current epoch");
    commit(stage(1)).unwrap();
    assert!(commit(switch(0, 5)).is_err(), "no move to a new epoch");
    assert!(commit(switch(1, 1)).is_err(), "not past the applied index");
    commit(switch(1, 5)).unwrap();
    assert!(
        commit(apply_at(0, 6)).is_err(),
        "an apply that raced the switch"
    );
    commit(apply_at(1, 6)).unwrap();
    let truncate = |after| Change::Truncate { agent: A, after };
    assert!(commit(truncate(5)).is_err(), "below the applied index");
    commit(truncate(6)).unwrap();
    // An install's first chunk into an epoch still holding rows.
    let rows = |key: u8| vec![(vec![1, key], vec![key])];
    commit(Change::Stage {
        agent: A,
        epoch: 2,
        first: true,
        rows: rows(1),
    })
    .unwrap();
    commit(Change::Stage {
        agent: A,
        epoch: 2,
        first: false,
        rows: rows(2),
    })
    .unwrap();
    assert!(
        commit(Change::Stage {
            agent: A,
            epoch: 2,
            first: true,
            rows: rows(3),
        })
        .is_err(),
        "not cleared"
    );
    assert!(
        commit(compact(5)).is_err(),
        "at the log start the switch set"
    );
}

#[test]
fn a_retirement_goes_only_into_an_empty_epoch() {
    let dir = tempfile::tempdir().unwrap();
    let writer = writer(dir.path());
    let commit = |change| smol::block_on(writer.commit(vec![change]));
    let retire = |epoch| Change::Retire {
        agent: A,
        epoch,
        hard: HardState::default(),
        floor: (7, 2),
    };
    commit(apply(1)).unwrap();
    commit(Change::Stage {
        agent: A,
        epoch: 1,
        first: true,
        rows: vec![(vec![1, 1], vec![1])],
    })
    .unwrap();
    assert!(commit(retire(0)).is_err(), "the current epoch");
    assert!(commit(retire(1)).is_err(), "an epoch holding rows");
    commit(retire(2)).unwrap();
    commit(Change::Apply {
        agent: A,
        epoch: 2,
        index: 1,
        writes: Vec::new(),
    })
    .unwrap();
    // The last log position it held stays, for the votes it gives.
    drop(writer);
    let store = Fjall::open(dir.path()).unwrap();
    assert_eq!(store.raft(A).unwrap().vote_floor, Some((7, 2)));
}

/// Holds every commit until released.
struct Hold(AtomicBool);

impl Hooks for Hold {
    fn before_commit(&self) {
        while self.0.load(Ordering::Relaxed) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

#[test]
fn a_held_writer_reports_a_stall_until_it_drains() {
    let dir = tempfile::tempdir().unwrap();
    let hold = Arc::new(Hold(AtomicBool::new(true)));
    let writer = Arc::new(StorageThread::spawn_with(
        Fjall::open(dir.path()).unwrap(),
        Arc::clone(&hold) as Arc<dyn Hooks>,
        Duration::from_millis(50),
    ));
    assert!(!writer.stalled());
    let pending = {
        let writer = Arc::clone(&writer);
        std::thread::spawn(move || smol::block_on(writer.commit(vec![hard(1, true)])))
    };
    // Stalled once the commit has waited past the 50 ms, however late its
    // thread reaches the writer; the bound only fails a writer that never
    // reports one.
    let until = Instant::now() + Duration::from_secs(30);
    while !writer.stalled() {
        assert!(Instant::now() < until, "the writer never stalled");
        std::thread::sleep(Duration::from_millis(5));
    }
    hold.0.store(false, Ordering::Relaxed);
    pending.join().unwrap().unwrap();
    assert!(!writer.stalled());
}

/// Holds the first group's commits until released, then each sync until
/// released, saying when one starts.
struct Syncs {
    hold: AtomicBool,
    /// The writer reached the hold.
    held: AtomicBool,
    syncing: Mutex<Option<mpsc::Sender<()>>>,
    synced: Mutex<mpsc::Receiver<()>>,
}

impl Hooks for Syncs {
    fn before_commit(&self) {
        if self.hold.load(Ordering::SeqCst) {
            self.held.store(true, Ordering::SeqCst);
        }
        while self.hold.load(Ordering::SeqCst) {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn fail_sync(&self) -> bool {
        if let Some(syncing) = &*self.syncing.lock().unwrap() {
            let _ = syncing.send(());
            let _ = self.synced.lock().unwrap().recv();
        }
        false
    }
}

/// A writer whose first commit waits for the hold's release, with the
/// commits `queued` sent behind it in their order, all in its next group;
/// the syncs held, each started told on the receiver given back.
fn queued_behind_a_held_commit(
    dir: &std::path::Path,
    queued: Vec<Vec<Change>>,
) -> (
    Arc<StorageThread>,
    Vec<mpsc::Receiver<Result<(), String>>>,
    mpsc::Receiver<()>,
    mpsc::Sender<()>,
) {
    let (syncing, started) = mpsc::channel();
    let (release, synced) = mpsc::channel();
    let hooks = Arc::new(Syncs {
        hold: AtomicBool::new(true),
        held: AtomicBool::new(false),
        syncing: Mutex::new(None),
        synced: Mutex::new(synced),
    });
    let writer = Arc::new(StorageThread::spawn(
        Fjall::open(dir).unwrap(),
        Arc::clone(&hooks) as Arc<dyn Hooks>,
    ));
    // Each commit sent here, in order (its first poll sends it), then
    // waited for on a thread of its own.
    let submit = |changes: Vec<Change>| {
        let (done, answered) = mpsc::channel();
        let committing = Arc::clone(&writer);
        let mut commit = Box::pin(async move { committing.commit(changes).await });
        assert!(smol::block_on(smol::future::poll_once(&mut commit)).is_none());
        std::thread::spawn(move || {
            let _ = done.send(smol::block_on(commit));
        });
        answered
    };
    // The first group: a commit alone, held before it is written, so the
    // rest are drained together after it.
    let first = submit(vec![hard(1, false)]);
    while !hooks.held.load(Ordering::SeqCst) {
        std::thread::sleep(Duration::from_millis(1));
    }
    let answers = queued.into_iter().map(submit).collect();
    *hooks.syncing.lock().unwrap() = Some(syncing);
    hooks.hold.store(false, Ordering::SeqCst);
    first.recv().unwrap().unwrap();
    (writer, answers, started, release)
}

const B: AgentId = AgentId(2);

/// An apply queued behind another agent's synced commit in one group is
/// written and answered without waiting for that commit's sync.
#[test]
fn an_unsynced_commit_does_not_wait_for_another_agents_sync() {
    let dir = tempfile::tempdir().unwrap();
    let other = Change::Apply {
        agent: B,
        epoch: 0,
        index: 1,
        writes: Vec::new(),
    };
    let (writer, answers, started, release) =
        queued_behind_a_held_commit(dir.path(), vec![vec![hard(2, true)], vec![other]]);
    started.recv().unwrap();
    answers[1]
        .recv_timeout(Duration::from_secs(30))
        .expect("the apply answered while the sync is held")
        .unwrap();
    assert!(
        answers[0].try_recv().is_err(),
        "the synced commit answered before its sync"
    );
    assert_eq!(writer.durably_applied(B), 0, "durable before the sync");
    release.send(()).unwrap();
    answers[0].recv().unwrap().unwrap();
    assert_eq!(
        writer.durably_applied(B),
        1,
        "the sync covers the apply before it"
    );
}

/// An agent's unsynced commit behind its own synced one in a group waits
/// for that sync: an agent's commits keep their order.
#[test]
fn an_agents_unsynced_commit_waits_for_its_earlier_sync() {
    let dir = tempfile::tempdir().unwrap();
    let (_writer, answers, started, release) =
        queued_behind_a_held_commit(dir.path(), vec![vec![hard(2, true)], vec![apply(1)]]);
    started.recv().unwrap();
    assert!(
        answers[1].recv_timeout(Duration::from_millis(200)).is_err(),
        "the agent's apply answered before its earlier commit's sync"
    );
    release.send(()).unwrap();
    answers[0].recv().unwrap().unwrap();
    answers[1].recv().unwrap().unwrap();
}

/// A commit held back for an agent holds back that agent's later ones too,
/// though they need no sync: an unsynced commit of A and B behind B's
/// synced one, then A's apply.
#[test]
fn a_commit_held_back_holds_back_its_agents_later_ones() {
    let dir = tempfile::tempdir().unwrap();
    let apply_of = |agent, index| Change::Apply {
        agent,
        epoch: 0,
        index,
        writes: Vec::new(),
    };
    let both = vec![apply_of(B, 1), apply(1)];
    let (_writer, answers, started, release) = queued_behind_a_held_commit(
        dir.path(),
        vec![
            vec![Change::Hard {
                agent: B,
                hard: HardState {
                    term: 1,
                    vote: None,
                    commit: 0,
                },
                sync: true,
            }],
            both,
            vec![apply(2)],
        ],
    );
    started.recv().unwrap();
    assert!(
        answers[2].recv_timeout(Duration::from_millis(200)).is_err(),
        "A's later apply answered before its earlier one"
    );
    release.send(()).unwrap();
    for answer in &answers {
        answer.recv().unwrap().unwrap();
    }
}

/// Fails its first sync, as a failed fsync does.
struct FailFirstSync(AtomicBool);

impl Hooks for FailFirstSync {
    fn fail_sync(&self) -> bool {
        self.0.swap(false, Ordering::SeqCst)
    }
}

/// A group's sync failing after its unsynced part was answered stops the
/// writer, and moves no applied index to durable.
#[test]
fn a_failed_sync_after_the_unsynced_part_stops_the_writer() {
    let dir = tempfile::tempdir().unwrap();
    let writer = StorageThread::spawn(
        Fjall::open(dir.path()).unwrap(),
        Arc::new(FailFirstSync(AtomicBool::new(true))),
    );
    let other = Change::Apply {
        agent: B,
        epoch: 0,
        index: 1,
        writes: Vec::new(),
    };
    let (synced, unsynced) = smol::block_on(smol::future::zip(
        writer.commit(vec![hard(1, true)]),
        writer.commit(vec![other]),
    ));
    assert!(synced.is_err());
    // Its own flush, or after the failure: answered either way.
    let _ = unsynced;
    assert!(writer.failed());
    assert_eq!(writer.durably_applied(B), 0);
    assert!(smol::block_on(writer.commit(vec![apply(1)])).is_err());
}
