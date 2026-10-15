use std::fs::OpenOptions;
use std::io::Write as _;
use std::time::Duration;

use vos_wire::ids::AgentId;

use super::collect::Cutoffs;
use super::index::segment_key;
use super::*;
use crate::NoHooks;
use crate::storage::StorageThread;
use crate::store::{LogEntry, PersistMode};

fn bytes(seed: u8, len: usize) -> Arc<Vec<u8>> {
    Arc::new(
        (0..len)
            .map(|at| (at as u8).wrapping_mul(31) ^ seed)
            .collect(),
    )
}

fn put(blobs: &Blobs, bytes: &Arc<Vec<u8>>) -> BlobRef {
    put_kept(blobs, bytes, Keep::Aged)
}

fn put_kept(blobs: &Blobs, bytes: &Arc<Vec<u8>>, keep: Keep) -> BlobRef {
    let blob = blob_ref(bytes);
    smol::block_on(blobs.put_kept(blob, Arc::clone(bytes), keep)).unwrap();
    blob
}

/// One horizon for every blob.
fn horizons(horizon: Duration) -> Horizons {
    Horizons {
        named: horizon,
        aged: horizon,
    }
}

/// Set `blob`'s last put `ago` before now.
fn age(blobs: &Blobs, store: &Fjall, blob: &BlobRef, ago: Duration) {
    let aged = Location {
        time: now() - ago.as_millis() as u64,
        ..blobs.location(&blob.hash).unwrap().unwrap()
    };
    store
        .blobs()
        .insert(location_key(&blob.hash), aged.encode())
        .unwrap();
}

#[test]
fn blobs_round_trip_and_survive_a_reopen() {
    let dir = tempfile::tempdir().unwrap();
    let store = Fjall::open(dir.path().join("store")).unwrap();
    let blobs = Blobs::open_with(dir.path().join("blobs"), &store, 4096).unwrap();
    let written: Vec<_> = (0..6).map(|seed| bytes(seed, 1500)).collect();
    let refs: Vec<_> = written.iter().map(|bytes| put(&blobs, bytes)).collect();
    for (blob, bytes) in refs.iter().zip(&written) {
        assert_eq!(
            blobs.get(&blob.hash).unwrap().as_ref(),
            Some(bytes.as_ref())
        );
    }
    assert!(!blobs.contains(&[7; 32]).unwrap());
    assert_eq!(blobs.get(&[7; 32]).unwrap(), None);
    // 4 KiB segments hold two records each.
    let segments = std::fs::read_dir(dir.path().join("blobs")).unwrap().count();
    assert_eq!(segments, 3);
    drop(blobs);
    drop(store);

    let store = Fjall::open(dir.path().join("store")).unwrap();
    let blobs = Blobs::open_with(dir.path().join("blobs"), &store, 4096).unwrap();
    for (blob, bytes) in refs.iter().zip(&written) {
        assert_eq!(
            blobs.get(&blob.hash).unwrap().as_ref(),
            Some(bytes.as_ref())
        );
    }
}

#[test]
fn open_indexes_a_segment_tail_and_cuts_a_torn_record() {
    let dir = tempfile::tempdir().unwrap();
    let blob_dir = dir.path().join("blobs");
    let (first, second) = {
        let store = Fjall::open(dir.path().join("store")).unwrap();
        let blobs = Blobs::open(&blob_dir, &store).unwrap();
        let first = put(&blobs, &bytes(1, 100));
        let second = put(&blobs, &bytes(2, 100));
        // The index rows are lost, as a crash may lose them.
        let mut batch = store.database().batch();
        batch.remove(store.blobs(), location_key(&second.hash));
        batch.remove(store.blobs(), segment_key(0));
        batch.commit().unwrap();
        (first, second)
    };
    // A torn record after the second.
    let segment = segment_path(&blob_dir, 0);
    let mut file = OpenOptions::new().append(true).open(&segment).unwrap();
    file.write_all(&MAGIC).unwrap();
    file.write_all(&100u64.to_be_bytes()).unwrap();
    file.write_all(&[3; 20]).unwrap();
    drop(file);
    let torn_len = std::fs::metadata(&segment).unwrap().len();

    let store = Fjall::open(dir.path().join("store")).unwrap();
    let blobs = Blobs::open(&blob_dir, &store).unwrap();
    assert!(blobs.contains(&first.hash).unwrap());
    assert!(
        blobs.contains(&second.hash).unwrap(),
        "re-indexed from the segment"
    );
    assert_eq!(blobs.get(&second.hash).unwrap().unwrap(), *bytes(2, 100));
    assert_eq!(
        std::fs::metadata(&segment).unwrap().len(),
        torn_len - 4 - 8 - 20,
        "the torn record is cut"
    );
    // The next put follows the cut.
    let third = put(&blobs, &bytes(3, 100));
    assert_eq!(blobs.get(&third.hash).unwrap().unwrap(), *bytes(3, 100));
}

#[test]
fn open_drops_an_indexed_record_torn_anyway() {
    let dir = tempfile::tempdir().unwrap();
    let blob_dir = dir.path().join("blobs");
    let (first, second) = {
        let store = Fjall::open(dir.path().join("store")).unwrap();
        let blobs = Blobs::open(&blob_dir, &store).unwrap();
        (put(&blobs, &bytes(1, 500)), put(&blobs, &bytes(2, 500)))
    };
    // Both are indexed; the disk loses the second's last bytes anyway.
    let segment = segment_path(&blob_dir, 0);
    let len = std::fs::metadata(&segment).unwrap().len();
    let file = OpenOptions::new().write(true).open(&segment).unwrap();
    file.set_len(len - 10).unwrap();
    drop(file);

    let store = Fjall::open(dir.path().join("store")).unwrap();
    let blobs = Blobs::open(&blob_dir, &store).unwrap();
    assert_eq!(blobs.get(&first.hash).unwrap().unwrap(), *bytes(1, 500));
    assert!(
        !blobs.contains(&second.hash).unwrap(),
        "the torn record is gone"
    );
    // It can be stored again.
    put(&blobs, &bytes(2, 500));
    assert_eq!(blobs.get(&second.hash).unwrap().unwrap(), *bytes(2, 500));
}

#[test]
fn collection_keeps_referenced_pinned_and_young_blobs() {
    let dir = tempfile::tempdir().unwrap();
    let store = Fjall::open(dir.path().join("store")).unwrap();
    let writer = StorageThread::spawn(store.clone(), Arc::new(NoHooks));
    let blobs = Blobs::open_with(dir.path().join("blobs"), &store, 4096).unwrap();
    let named = put(&blobs, &bytes(1, 1500));
    let pinned = put(&blobs, &bytes(2, 1500));
    let dead: Vec<_> = (3..7).map(|seed| put(&blobs, &bytes(seed, 1500))).collect();
    let entry = LogEntry {
        blobs: vec![named],
        ..LogEntry::result(1, Vec::new())
    };
    let mut batch = store.batch();
    batch.append(AgentId(1), 1, &entry);
    batch.pin(&pinned.hash, AgentId(1));
    batch.commit(PersistMode::SyncAll).unwrap();

    // Everything is younger than a day: nothing goes.
    let kept =
        smol::block_on(blobs.collect(&writer, horizons(Duration::from_secs(86_400)), &|| false))
            .unwrap();
    assert_eq!(kept.removed, 0);
    // With no horizon, the unnamed and unpinned blobs go, and segments
    // left empty or sparse are deleted, their live blobs moved.
    let collected =
        smol::block_on(blobs.collect(&writer, horizons(Duration::ZERO), &|| false)).unwrap();
    assert_eq!(collected.removed, dead.len());
    assert!(collected.segments_deleted >= 1, "{collected:?}");
    for blob in &dead {
        assert!(!blobs.contains(&blob.hash).unwrap());
    }
    assert_eq!(blobs.get(&named.hash).unwrap().unwrap(), *bytes(1, 1500));
    assert_eq!(blobs.get(&pinned.hash).unwrap().unwrap(), *bytes(2, 1500));
    assert_eq!(blobs.pinned().unwrap(), vec![pinned.hash]);
    drop(blobs);
    drop(writer);
    drop(store);
    // And all of it holds after a reopen.
    let store = Fjall::open(dir.path().join("store")).unwrap();
    let blobs = Blobs::open_with(dir.path().join("blobs"), &store, 4096).unwrap();
    assert_eq!(blobs.get(&named.hash).unwrap().unwrap(), *bytes(1, 1500));
    assert_eq!(blobs.get(&pinned.hash).unwrap().unwrap(), *bytes(2, 1500));
    for blob in &dead {
        assert!(!blobs.contains(&blob.hash).unwrap());
    }
}

#[test]
fn a_touch_keeps_a_candidate_from_a_removal_after_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = Fjall::open(dir.path().join("store")).unwrap();
    let blobs = Blobs::open(dir.path().join("blobs"), &store).unwrap();
    let kept = put(&blobs, &bytes(1, 300));
    let dropped = put(&blobs, &bytes(2, 300));
    // Both aged out: candidates of a collection deciding now.
    for blob in [kept, dropped] {
        let old = Location {
            time: 0,
            ..blobs.location(&blob.hash).unwrap().unwrap()
        };
        store
            .blobs()
            .insert(location_key(&blob.hash), old.encode())
            .unwrap();
    }
    let cutoff = now() - 1;
    // An entry comes to rely on one: its host touches it first.
    let touched = smol::block_on(blobs.touch(vec![kept.hash, [9; 32]])).unwrap();
    assert_eq!(touched, vec![kept.hash], "only stored blobs answer");
    let removed = smol::block_on(blobs.request(|done| Request::Remove {
        candidates: vec![kept.hash, dropped.hash],
        cutoffs: Cutoffs {
            named: cutoff,
            aged: cutoff,
        },
        done,
    }))
    .unwrap();
    assert_eq!(removed, 1);
    assert!(blobs.contains(&kept.hash).unwrap());
    assert!(!blobs.contains(&dropped.hash).unwrap());
}

#[test]
fn a_put_of_a_stored_blob_refreshes_its_age() {
    let dir = tempfile::tempdir().unwrap();
    let store = Fjall::open(dir.path().join("store")).unwrap();
    let writer = StorageThread::spawn(store.clone(), Arc::new(NoHooks));
    let blobs = Blobs::open(dir.path().join("blobs"), &store).unwrap();
    let data = bytes(9, 300);
    let blob = put(&blobs, &data);
    // Age it, as if put long ago, then put it again.
    let old = Location {
        time: 0,
        ..blobs.location(&blob.hash).unwrap().unwrap()
    };
    store
        .blobs()
        .insert(location_key(&blob.hash), old.encode())
        .unwrap();
    put(&blobs, &data);
    let kept =
        smol::block_on(blobs.collect(&writer, horizons(Duration::from_secs(3_600)), &|| false))
            .unwrap();
    assert_eq!(kept.removed, 0);
    assert!(blobs.contains(&blob.hash).unwrap());
    let segment_records = std::fs::metadata(segment_path(&dir.path().join("blobs"), 0))
        .unwrap()
        .len();
    assert_eq!(segment_records, HEADER + 300, "stored once");
}

/// A blob kept as named goes by its own, brief horizon, an aged one by
/// the store's; a hold keeps either, whatever its age.
#[test]
fn each_keep_ages_by_its_horizon_and_a_hold_outlasts_both() {
    let dir = tempfile::tempdir().unwrap();
    let store = Fjall::open(dir.path().join("store")).unwrap();
    let writer = StorageThread::spawn(store.clone(), Arc::new(NoHooks));
    let blobs = Blobs::open(dir.path().join("blobs"), &store).unwrap();
    let named = put_kept(&blobs, &bytes(1, 300), Keep::Named);
    let aged = put_kept(&blobs, &bytes(2, 300), Keep::Aged);
    let held = put_kept(&blobs, &bytes(3, 300), Keep::Named);
    let hold = blobs.hold(held.hash);
    for blob in [named, aged, held] {
        age(&blobs, &store, &blob, Duration::from_secs(60));
    }
    let horizons = Horizons {
        named: Duration::from_secs(10),
        aged: Duration::from_secs(3_600),
    };
    let collect = || smol::block_on(blobs.collect(&writer, horizons, &|| false)).unwrap();
    assert_eq!(collect().removed, 1);
    assert!(!blobs.contains(&named.hash).unwrap());
    assert!(blobs.contains(&aged.hash).unwrap(), "within its horizon");
    assert!(blobs.contains(&held.hash).unwrap(), "held");
    // A second hold outlives the first.
    let again = blobs.hold(held.hash);
    drop(hold);
    assert_eq!(collect().removed, 0);
    drop(again);
    assert_eq!(collect().removed, 1);
    assert!(!blobs.contains(&held.hash).unwrap());
}

/// A hold taken once a collection chose its candidates still keeps the
/// blob: the writer checks again as it removes.
#[test]
fn a_hold_keeps_a_candidate_from_a_removal_after_it() {
    let dir = tempfile::tempdir().unwrap();
    let store = Fjall::open(dir.path().join("store")).unwrap();
    let blobs = Blobs::open(dir.path().join("blobs"), &store).unwrap();
    let blob = put_kept(&blobs, &bytes(1, 300), Keep::Named);
    age(&blobs, &store, &blob, Duration::from_secs(60));
    let cutoff = now() - 1;
    let remove = || {
        smol::block_on(blobs.request(|done| Request::Remove {
            candidates: vec![blob.hash],
            cutoffs: Cutoffs {
                named: cutoff,
                aged: cutoff,
            },
            done,
        }))
        .unwrap()
    };
    let hold = blobs.hold(blob.hash);
    assert_eq!(remove(), 0);
    drop(hold);
    assert_eq!(remove(), 1);
}

/// A blob put both ways keeps the longer, and moving it keeps that; a
/// row without its keep, or with one this build does not know, reads as
/// aged.
#[test]
fn a_blob_keeps_the_longer_of_its_keeps() {
    let dir = tempfile::tempdir().unwrap();
    let store = Fjall::open(dir.path().join("store")).unwrap();
    let blobs = Blobs::open(dir.path().join("blobs"), &store).unwrap();
    let keep = |blob: &BlobRef| blobs.location(&blob.hash).unwrap().unwrap().keep;
    let data = bytes(1, 300);
    let blob = put_kept(&blobs, &data, Keep::Named);
    assert_eq!(keep(&blob), Keep::Named);
    put_kept(&blobs, &data, Keep::Aged);
    assert_eq!(keep(&blob), Keep::Aged);
    put_kept(&blobs, &data, Keep::Named);
    assert_eq!(keep(&blob), Keep::Aged);
    smol::block_on(blobs.send(blob, Arc::clone(&data), Keep::Named, true)).unwrap();
    assert_eq!(keep(&blob), Keep::Aged, "moved");
    let location = blobs.location(&blob.hash).unwrap().unwrap();
    let named = Location {
        keep: Keep::Named,
        ..location
    };
    let mut unknown = named.encode();
    unknown[32] = 7;
    for row in [&named.encode()[..32], &unknown[..]] {
        assert_eq!(Location::decode(row), Some(location));
    }
}
