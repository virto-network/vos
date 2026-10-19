use vos_wire::ids::{InstanceId, SessionId};
use vos_wire::keys;
use vos_wire::result::Write;

use super::*;

const A: AgentId = AgentId(1);
const B: AgentId = AgentId(2);

fn put(key: Vec<u8>, value: &[u8]) -> Write {
    Write {
        key,
        value: Some(value.to_vec()),
    }
}

fn row(instance: u32, index: u64) -> Vec<u8> {
    [
        keys::table_prefix(InstanceId(instance), 7),
        index.to_be_bytes().to_vec(),
    ]
    .concat()
}

fn rows(view: &Snapshot, agent: AgentId, prefix: &[u8], after: Option<&[u8]>) -> Vec<Vec<u8>> {
    view.scan(agent, prefix, after)
        .map(|row| row.unwrap().0)
        .collect()
}

#[test]
fn applies_writes_per_agent_with_their_applied_index() {
    let dir = tempfile::tempdir().unwrap();
    let store = Fjall::open(dir.path()).unwrap();
    let session = keys::session(SessionId(9));
    let mut batch = store.batch();
    batch.apply(
        A,
        0,
        1,
        &[put(row(0, 1), b"one"), put(session.clone(), b"mark")],
    );
    batch.apply(B, 0, 4, &[put(row(0, 1), b"other")]);
    batch.commit(PersistMode::SyncAll).unwrap();

    let view = store.snapshot();
    assert_eq!(
        view.get(A, &row(0, 1)).unwrap().as_deref(),
        Some(&b"one"[..])
    );
    assert_eq!(
        view.get(B, &row(0, 1)).unwrap().as_deref(),
        Some(&b"other"[..])
    );
    assert_eq!(
        view.get(A, &session).unwrap().as_deref(),
        Some(&b"mark"[..])
    );
    assert_eq!(view.get(B, &session).unwrap(), None);
    assert_eq!(view.applied(A).unwrap(), Some(1));
    assert_eq!(view.applied(B).unwrap(), Some(4));
    assert_eq!(view.applied(AgentId(3)).unwrap(), None);

    let mut batch = store.batch();
    batch.apply(
        A,
        0,
        2,
        &[Write {
            key: row(0, 1),
            value: None,
        }],
    );
    batch.commit(PersistMode::Buffer).unwrap();
    assert_eq!(
        view.get(A, &row(0, 1)).unwrap().as_deref(),
        Some(&b"one"[..]),
        "a snapshot keeps its view"
    );
    assert_eq!(store.snapshot().get(A, &row(0, 1)).unwrap(), None);
    assert_eq!(store.snapshot().applied(A).unwrap(), Some(2));
}

#[test]
fn scans_stay_inside_their_prefix_and_agent() {
    let dir = tempfile::tempdir().unwrap();
    let store = Fjall::open(dir.path()).unwrap();
    let mut batch = store.batch();
    let writes: Vec<_> = (0..5)
        .map(|index| put(row(1, index), b"v"))
        .chain([put(row(0, 9), b"v"), put(row(2, 0), b"v")])
        .collect();
    let mut writes = writes;
    writes.push(put(keys::session(SessionId(1)), b"mark"));
    batch.apply(A, 0, 1, &writes);
    batch.apply(AgentId(0x0100_0000), 0, 1, &[put(row(1, 9), b"v")]);
    batch.apply(B, 0, 1, &[put(row(1, 9), b"v")]);
    batch.commit(PersistMode::SyncAll).unwrap();

    let view = store.snapshot();
    let table = keys::table_prefix(InstanceId(1), 7);
    let all: Vec<_> = (0..5).map(|index| row(1, index)).collect();
    assert_eq!(rows(&view, A, &table, None), all);
    assert_eq!(rows(&view, A, &table, Some(&row(1, 2))), all[3..]);
    assert_eq!(
        rows(&view, A, &table, Some(&row(1, 4))),
        Vec::<Vec<u8>>::new()
    );
    assert_eq!(
        rows(&view, A, &table, Some(&row(0, 9))),
        all,
        "a cursor before the prefix starts at the prefix"
    );
    assert_eq!(
        rows(&view, A, &keys::instance_rows(InstanceId(1)), None),
        all
    );
    assert_eq!(
        rows(&view, A, &[0x00], None),
        vec![keys::session(SessionId(1))],
        "system keys are a partition of their own; the applied index is not an agent key"
    );
    assert_eq!(rows(&view, B, &[0x00], None), Vec::<Vec<u8>>::new());
}

#[test]
fn later_writes_to_a_key_win_within_a_batch() {
    let dir = tempfile::tempdir().unwrap();
    let store = Fjall::open(dir.path()).unwrap();
    let delete = |key: Vec<u8>| Write { key, value: None };
    let mut batch = store.batch();
    batch.apply(
        A,
        0,
        1,
        &[
            put(row(0, 1), b"first"),
            put(row(0, 1), b"second"),
            put(row(0, 2), b"gone"),
            delete(row(0, 2)),
            delete(row(0, 3)),
            put(row(0, 3), b"back"),
        ],
    );
    batch.commit(PersistMode::Buffer).unwrap();
    let view = store.snapshot();
    assert_eq!(
        view.get(A, &row(0, 1)).unwrap().as_deref(),
        Some(&b"second"[..])
    );
    assert_eq!(view.get(A, &row(0, 2)).unwrap(), None);
    assert_eq!(
        view.get(A, &row(0, 3)).unwrap().as_deref(),
        Some(&b"back"[..])
    );
}

/// A snapshot sees the applied index and the state rows, which live in
/// different partitions, as of one commit, while commits continue.
#[test]
fn snapshots_agree_across_partitions_under_concurrent_writes() {
    const SLOTS: u64 = 16;
    const RESULTS: u64 = 400;
    let dir = tempfile::tempdir().unwrap();
    let store = Fjall::open(dir.path()).unwrap();
    // Work result i writes i into slots i, i + 1 and i + 2 (mod SLOTS):
    // after result n, slot s holds the last i <= n that wrote it.
    let writes = |index: u64| -> Vec<Write> {
        (0..3)
            .map(|k| put(row(0, (index + k) % SLOTS), &index.to_be_bytes()))
            .collect()
    };
    let expected = |applied: u64, slot: u64| -> Option<u64> {
        (1..=applied)
            .rev()
            .find(|index| (0..3).any(|k| (index + k) % SLOTS == slot))
    };
    std::thread::scope(|scope| {
        scope.spawn(|| {
            for index in 1..=RESULTS {
                let mut batch = store.batch();
                batch.apply(A, 0, index, &writes(index));
                batch.commit(PersistMode::Buffer).unwrap();
            }
        });
        let mut seen = 0;
        while seen < RESULTS {
            let view = store.snapshot();
            let applied = view.applied(A).unwrap().unwrap_or(0);
            for slot in 0..SLOTS {
                let value = view
                    .get(A, &row(0, slot))
                    .unwrap()
                    .map(|bytes| u64::from_be_bytes(bytes[..].try_into().unwrap()));
                assert_eq!(value, expected(applied, slot), "slot {slot} at {applied}");
            }
            assert!(applied >= seen, "a later snapshot never goes back");
            seen = applied;
        }
    });
}

/// A flipped bit inside a committed batch is not a torn tail: the store
/// refuses to open rather than drop or replay it.
#[test]
fn a_corrupt_committed_batch_stops_recovery() {
    // Incompressible, so the journal holds it as written.
    let mut seed = 0x2545_f491_4f6c_dd1d_u64;
    let value: Vec<u8> = (0..256)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        })
        .collect();
    let dir = tempfile::tempdir().unwrap();
    {
        let store = Fjall::open(dir.path()).unwrap();
        let mut batch = store.batch();
        batch.apply(A, 0, 1, &[put(row(0, 1), &value)]);
        batch.commit(PersistMode::SyncAll).unwrap();
    }
    let mut pending = vec![dir.path().to_path_buf()];
    let mut flipped = false;
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(&path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().is_none_or(|extension| extension != "jnl") {
                continue;
            }
            let mut bytes = std::fs::read(&path).unwrap();
            if let Some(at) = bytes
                .windows(value.len())
                .position(|window| window == value)
            {
                bytes[at + 100] ^= 0x01;
                std::fs::write(&path, bytes).unwrap();
                flipped = true;
            }
        }
    }
    assert!(flipped, "the value is in a journal");
    match Fjall::open(dir.path()) {
        Err(Error::JournalRecovery(fjall::JournalRecoveryError::ChecksumMismatch)) => {}
        Err(other) => panic!("unexpected error: {other:?}"),
        Ok(_) => panic!("opened a store with a corrupt committed batch"),
    }
}

fn entry(term: u64, body: &[u8]) -> LogEntry {
    LogEntry::result(term, body.to_vec())
}

fn indices(store: &Fjall, agent: AgentId) -> Vec<(u64, u64)> {
    store
        .log_range(agent, 0, u64::MAX, usize::MAX)
        .unwrap()
        .into_iter()
        .map(|(index, entry)| (index, entry.term))
        .collect()
}

#[test]
fn raft_rows_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let store = Fjall::open(dir.path()).unwrap();
    assert_eq!(store.raft(A).unwrap(), RaftRows::default());
    let hard = HardState {
        term: 7,
        vote: Some(2),
        commit: 4,
    };
    let membership = Membership {
        index: Some(3),
        members: vec![1, 2, 4],
        joint_old: Some(vec![1, 2, 3]),
    };
    let mut batch = store.batch();
    for index in 1..=5 {
        batch.append(A, index, &entry(index / 2 + 1, &[index as u8]));
    }
    batch.hard_state(A, &hard);
    batch.membership(A, &membership);
    batch.apply(A, 0, 3, &[]);
    batch.commit(PersistMode::SyncAll).unwrap();
    let at_start = Membership {
        index: Some(1),
        members: vec![1, 2, 3],
        joint_old: None,
    };
    let mut batch = store.batch();
    batch.compact(A, 2, 2, Some(&at_start));
    batch.commit(PersistMode::Buffer).unwrap();
    drop(store);

    let store = Fjall::open(dir.path()).unwrap();
    let rows = store.raft(A).unwrap();
    assert_eq!(rows.hard, hard);
    assert_eq!(rows.membership, Some(membership));
    assert_eq!(rows.applied, 3);
    assert_eq!(rows.log_start, (2, 2));
    assert_eq!(rows.log_start_membership, Some(at_start));
    assert_eq!(
        rows.log.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
        vec![3, 4, 5]
    );
    assert_eq!(
        store.raft(B).unwrap(),
        RaftRows::default(),
        "another agent's rows"
    );
}

#[test]
fn truncation_removes_stored_and_batched_entries() {
    let dir = tempfile::tempdir().unwrap();
    let store = Fjall::open(dir.path()).unwrap();
    let mut batch = store.batch();
    for index in 1..=5 {
        batch.append(A, index, &entry(1, b"old"));
    }
    batch.append(B, 9, &entry(1, b"other agent"));
    batch.commit(PersistMode::SyncAll).unwrap();
    // One batch appends 6 and 7, then a new leader's write truncates
    // after 4 and appends its own 5.
    let mut batch = store.batch();
    batch.append(A, 6, &entry(1, b"old"));
    batch.append(A, 7, &entry(1, b"old"));
    batch.truncate(A, 4);
    batch.append(A, 5, &entry(2, b"new"));
    batch.commit(PersistMode::SyncAll).unwrap();
    assert_eq!(
        indices(&store, A),
        vec![(1, 1), (2, 1), (3, 1), (4, 1), (5, 2)]
    );
    assert_eq!(indices(&store, B), vec![(9, 1)]);
}

#[test]
fn a_log_range_stops_at_its_bytes_but_returns_one_entry() {
    let dir = tempfile::tempdir().unwrap();
    let store = Fjall::open(dir.path()).unwrap();
    let mut batch = store.batch();
    for index in 1..=4 {
        batch.append(A, index, &entry(1, &[0; 100]));
    }
    batch.commit(PersistMode::SyncAll).unwrap();
    let range = |max_bytes| {
        store
            .log_range(A, 2, 4, max_bytes)
            .unwrap()
            .into_iter()
            .map(|(index, _)| index)
            .collect::<Vec<_>>()
    };
    assert_eq!(range(1), vec![2]);
    assert_eq!(range(250), vec![2, 3]);
    assert_eq!(range(usize::MAX), vec![2, 3, 4]);
    assert!(store.log_range(A, 5, 9, usize::MAX).unwrap().is_empty());
}

fn switch_to(epoch: u8, index: u64) -> Switch {
    Switch {
        epoch,
        index,
        term: 2,
        hard: HardState {
            term: 2,
            vote: None,
            commit: index,
        },
        membership: Membership::default(),
        log_start_membership: None,
        truncate_after: None,
    }
}

/// A switch writes, in its one batch, the Raft rows a replica recovers
/// with its state: the hard state, the log's start, and the membership
/// in effect there and now.
#[test]
fn a_switch_writes_the_raft_rows_it_recovers_with() {
    let dir = tempfile::tempdir().unwrap();
    let store = Fjall::open(dir.path()).unwrap();
    let membership = Membership {
        index: Some(30),
        members: vec![1, 2, 4],
        joint_old: None,
    };
    let at_start = Membership {
        index: Some(12),
        members: vec![1, 2, 3],
        joint_old: None,
    };
    let switch = Switch {
        membership: membership.clone(),
        log_start_membership: Some(at_start.clone()),
        ..switch_to(1, 37)
    };
    let mut batch = store.batch();
    batch.switch(B, &switch);
    batch.commit(PersistMode::SyncAll).unwrap();
    let rows = store.raft(B).unwrap();
    assert_eq!(rows.hard, switch.hard);
    assert_eq!(rows.log_start, (37, 2));
    assert_eq!(rows.applied, 37);
    assert_eq!(rows.membership, Some(membership));
    assert_eq!(rows.log_start_membership, Some(at_start));
}

/// An export of one agent, staged under a new epoch of another and
/// switched to, gives the second the first's state; a snapshot taken
/// before the switch keeps reading the old epoch; the old epoch's rows
/// stay until dropped.
#[test]
fn a_staged_export_switches_in_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let store = Fjall::open(dir.path()).unwrap();
    let session = keys::session(SessionId(4));
    let mut batch = store.batch();
    let writes: Vec<Write> = (0..50)
        .map(|index| put(row(0, index), &index.to_be_bytes()))
        .chain([put(session.clone(), b"mark")])
        .collect();
    batch.apply(A, 0, 7, &writes);
    batch.append(A, 7, &LogEntry::result(2, vec![7]));
    batch.apply(B, 0, 3, &[put(row(0, 99), b"old")]);
    batch.commit(PersistMode::SyncAll).unwrap();

    let mut export = store.export(A).unwrap();
    assert_eq!((export.applied, export.term), (7, 2));
    let mut rows = Vec::new();
    let mut chunks = 0;
    while let Some(chunk) = export.next_chunk(200).unwrap() {
        chunks += 1;
        rows.extend(chunk);
    }
    assert!(chunks > 1, "read in chunks");
    assert_eq!(rows.len(), 51);
    assert_eq!(rows[0].0, session, "system keys first");

    let before = store.snapshot();
    let mut batch = store.batch();
    batch.stage(B, 1, &rows);
    batch.commit(PersistMode::Buffer).unwrap();
    assert_eq!(
        store.snapshot().get(B, &row(0, 1)).unwrap(),
        None,
        "staged, not live"
    );
    let mut batch = store.batch();
    batch.switch(B, &switch_to(1, 7));
    batch.commit(PersistMode::SyncAll).unwrap();

    let after = store.snapshot();
    assert_eq!(after.epoch(B).unwrap(), 1);
    assert_eq!(after.applied(B).unwrap(), Some(7));
    assert_eq!(
        after.get(B, &row(0, 1)).unwrap().as_deref(),
        Some(&1u64.to_be_bytes()[..])
    );
    assert_eq!(after.get(B, &row(0, 99)).unwrap(), None);
    assert_eq!(
        after.get(B, &session).unwrap().as_deref(),
        Some(&b"mark"[..])
    );
    // The earlier snapshot still reads the old epoch whole.
    assert_eq!(
        before.get(B, &row(0, 99)).unwrap().as_deref(),
        Some(&b"old"[..])
    );
    assert_eq!(before.get(B, &row(0, 1)).unwrap(), None);
    let raft = store.raft(B).unwrap();
    assert_eq!(raft.log_start, (7, 2));
    assert_eq!(raft.applied, 7);

    assert_eq!(store.stale_epochs(B).unwrap(), vec![0]);
    let mut batch = store.batch();
    batch.drop_epoch(B, 0, usize::MAX);
    batch.commit(PersistMode::Buffer).unwrap();
    assert!(store.stale_epochs(B).unwrap().is_empty());
    assert!(store.stale_epochs(A).unwrap().is_empty());
}

#[test]
fn logs_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let store = Fjall::open(dir.path()).unwrap();
    let entry = LogEntry::result(3, b"result".to_vec());
    let mut batch = store.batch();
    batch.append(A, 7, &entry);
    batch.commit(PersistMode::SyncAll).unwrap();
    assert_eq!(store.log_entry(A, 7).unwrap(), Some(entry));
    assert_eq!(store.log_entry(A, 8).unwrap(), None);
    assert_eq!(store.log_entry(B, 7).unwrap(), None);
    drop(store);

    let reopened = Fjall::open(dir.path()).unwrap();
    assert_eq!(reopened.log_entry(A, 7).unwrap().unwrap().term, 3);
}
