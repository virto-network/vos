//! A store snapshot sees each commit whole or not at all, while flushes and
//! compactions run beside the commits. lsm-tree published a flush's or a
//! compaction's sequence number as visible while a commit holding a lower
//! one was still inserting its rows, so a snapshot opened then saw part of
//! that commit, and more of it on each read (`support/lsm-tree`).

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use vos_node::store::{Fjall, PersistMode};
use vos_wire::ids::{AgentId, InstanceId};
use vos_wire::keys::{self, Transform};
use vos_wire::result::Write;

const AGENT: AgentId = AgentId(1);
const ROWS: u64 = 1_000;

/// The table the commits write, in the state partition.
fn table() -> Vec<u8> {
    keys::table_rows(InstanceId(0), 1, Transform::Ordered)
}

/// Row `row` of commit `index`, under a table whose old rows are deleted as
/// the commits go, so scans start among deletions.
fn key(index: u64, row: u64) -> Vec<u8> {
    [&table()[..], &index.to_be_bytes(), &row.to_be_bytes()].concat()
}

#[test]
fn snapshots_never_see_part_of_a_commit() {
    let dir = tempfile::tempdir().unwrap();
    let store = Fjall::open(dir.path()).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let writer = {
        let store = store.clone();
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut index = 0;
            while !stop.load(Ordering::SeqCst) {
                index += 1;
                let mut writes: Vec<Write> = (0..ROWS)
                    .map(|row| Write {
                        key: key(index, row),
                        value: Some(vec![1; 16]),
                    })
                    .collect();
                if index > 10 {
                    writes.extend((0..ROWS).map(|row| Write {
                        key: key(index - 10, row),
                        value: None,
                    }));
                }
                let mut batch = store.batch();
                batch.apply(AGENT, 0, index, &writes);
                batch.commit(PersistMode::Buffer).unwrap();
            }
        })
    };
    // The commits fill the state partition's memtable, which rotates and
    // is flushed once full: the flushes this test needs beside the reads.
    // Each rotation empties the active memtable, which the reads watch.
    let mut rotations = 0;
    let mut filled = 0;
    let started = Instant::now();
    let mut checks = 0u64;
    while started.elapsed() < Duration::from_secs(4) || rotations < 2 {
        assert!(
            started.elapsed() < Duration::from_secs(60),
            "the memtable rotated {rotations} times"
        );
        let bytes = store.state_memtable_bytes();
        if bytes < filled {
            rotations += 1;
        }
        filled = bytes;
        let snapshot = store.snapshot();
        let applied = snapshot.applied(AGENT).unwrap().unwrap_or(0);
        let from = key(applied.saturating_sub(9).max(1), 0);
        let mut counted = 0;
        for row in snapshot.scan(AGENT, &table(), Some(&from)) {
            let (key, _) = row.unwrap();
            let at = table().len();
            let index = u64::from_be_bytes(key[at..at + 8].try_into().unwrap());
            assert!(
                index <= applied,
                "a row of commit {index} in a snapshot at {applied}"
            );
            counted += 1;
        }
        // The last ten commits whole, but the row the scan starts after.
        if applied > 0 {
            assert_eq!(
                counted,
                applied.min(10) * ROWS - 1,
                "the last ten commits in a snapshot at {applied}"
            );
        }
        checks += 1;
    }
    stop.store(true, Ordering::SeqCst);
    writer.join().unwrap();
    assert!(checks > 100, "{checks} snapshots checked");
}
