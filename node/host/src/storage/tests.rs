use std::sync::atomic::AtomicBool;

use super::*;
use crate::NoHooks;

const A: AgentId = AgentId(1);

fn writer(dir: &std::path::Path) -> StorageThread {
    StorageThread::spawn(Fjall::open(dir).unwrap(), Arc::new(NoHooks))
}

fn apply(index: u64) -> Change {
    Change::Apply {
        agent: A,
        epoch: 0,
        index,
        writes: Vec::new(),
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
    let compact = |through| Change::Compact {
        agent: A,
        through,
        term: 1,
        membership: None,
    };
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
    let apply_at = |epoch, index| Change::Apply {
        agent: A,
        epoch,
        index,
        writes: Vec::new(),
    };
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
    let compact = |through| Change::Compact {
        agent: A,
        through,
        term: 1,
        membership: None,
    };
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
    std::thread::sleep(Duration::from_millis(100));
    assert!(writer.stalled());
    hold.0.store(false, Ordering::Relaxed);
    pending.join().unwrap().unwrap();
    assert!(!writer.stalled());
}
