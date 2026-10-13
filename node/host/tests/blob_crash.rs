//! Log entries and the blobs they name, killed mid-write: no surviving
//! entry lacks its blob (section 9.5, invariant 7).
//!
//! A child process appends entries that each name a blob, as a replica
//! does: some after storing the blob, some before (an append may arrive
//! ahead of its blob), and reports an entry only once both are durable.
//! It also applies each entry, compacts its log below what is durably
//! applied, leaves orphan blobs, and collects: dead blobs go, segments
//! (small here) are deleted or have their live blobs moved.
//! The test kills it at random moments, then reopens the store and the
//! blob store, which recovers its segments, and cuts the log at its first
//! entry missing a blob, as a node does on open. Later rounds tear the
//! journal's tail or the blob segment's, as a power loss could. After
//! each:
//!
//! - every surviving log entry's blob is stored and holds the bytes it
//!   was written with;
//! - every entry reported survives, but for a tear's reach: a journal's
//!   last batch, or the entries from one whose blob a segment tear took
//!   (collection may have moved an older blob to the tail);
//! - the log has no gap.

/// The allocator the node's binary runs on.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use vos_node::NoHooks;
use vos_node::blobs::{Blobs, blob_ref};
use vos_node::raft::recovery_cut;
use vos_node::storage::{Change, StorageThread};
use vos_node::store::{Fjall, LogEntry, Store};
use vos_wire::ids::AgentId;

const AGENT: AgentId = AgentId(1);
const ROUNDS: usize = 12;
/// Rounds from this one on tear a tail before reopening.
const TORN_FROM: usize = 6;
/// At most this many bytes of a blob segment are torn: less than one blob.
const BLOB_TEAR: u64 = 1024;
/// At most this many bytes of the journal are torn: less than one append.
const JOURNAL_TEAR: u64 = 64;
/// Each blob's size.
const BLOB: usize = 3000;
/// Segments hold a few blobs, so collection deletes and moves them.
const SEGMENT: u64 = 16 << 10;
const WRITER: &str = "VOS_BLOB_CRASH_WRITER";

/// Entry `index`'s blob.
fn blob_bytes(index: u64) -> Vec<u8> {
    let mut seed = index.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
    (0..BLOB)
        .map(|_| {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed as u8
        })
        .collect()
}

fn open(dir: &std::path::Path) -> (Fjall, Blobs) {
    let store = Fjall::open(dir.join("store")).unwrap();
    let blobs = Blobs::open_with(dir.join("blobs"), &store, SEGMENT).unwrap();
    (store, blobs)
}

fn writer(dir: &str) {
    let dir = std::path::Path::new(dir);
    let (store, blobs) = open(dir);
    let writer = StorageThread::spawn(store.clone(), Arc::new(NoHooks));
    writer.recovered(AGENT, store.raft(AGENT).unwrap().applied);
    let cut = recovery_cut(&store, &blobs, AGENT).unwrap();
    smol::block_on(writer.commit(cut.changes)).unwrap();
    let rows = store.raft(AGENT).unwrap();
    let mut log_start = rows.log_start.0;
    let mut index = rows.log.last().map_or(log_start, |(index, _)| *index);
    let commit = |changes| smol::block_on(writer.commit(changes)).unwrap();
    // What was appended before the crash is applied again.
    for at in rows.applied + 1..=index {
        commit(vec![Change::Apply {
            agent: AGENT,
            epoch: 0,
            index: at,
            writes: Vec::new(),
        }]);
    }
    loop {
        index += 1;
        let bytes = Arc::new(blob_bytes(index));
        let blob = blob_ref(&bytes);
        let entry = LogEntry {
            blobs: vec![blob],
            ..LogEntry::result(1, index.to_be_bytes().to_vec())
        };
        let append = Change::Append {
            agent: AGENT,
            index,
            entry,
        };
        if index.is_multiple_of(3) {
            // The append arrives ahead of its blob.
            smol::block_on(writer.commit(vec![append])).unwrap();
            smol::block_on(blobs.put(blob, bytes)).unwrap();
        } else {
            smol::block_on(blobs.put(blob, bytes)).unwrap();
            smol::block_on(writer.commit(vec![append])).unwrap();
        }
        println!("appended {index}");
        commit(vec![Change::Apply {
            agent: AGENT,
            epoch: 0,
            index,
            writes: Vec::new(),
        }]);
        if index.is_multiple_of(5) {
            // An orphan: a blob sent ahead of an append that never came.
            let orphan = Arc::new(blob_bytes(index | 1 << 40));
            smol::block_on(blobs.put(blob_ref(&orphan), orphan)).unwrap();
        }
        if index.is_multiple_of(7) {
            let durable = writer.durably_applied(AGENT);
            if durable > log_start + 4 {
                let through = durable - 3;
                commit(vec![Change::Compact {
                    agent: AGENT,
                    through,
                    term: 1,
                    membership: None,
                }]);
                log_start = through;
            }
            smol::block_on(blobs.collect(&writer, Duration::ZERO, &|| false)).unwrap();
        }
    }
}

fn main() {
    if let Ok(dir) = std::env::var(WRITER) {
        writer(&dir);
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let mut seed = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap()
        .as_nanos() as u64
        | 1;
    let mut random = move || {
        seed ^= seed << 13;
        seed ^= seed >> 7;
        seed ^= seed << 17;
        seed
    };
    let mut tore = 0;
    for round in 0..ROUNDS {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .env(WRITER, dir.path())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let mut reported: u64 = 0;
        for _ in 0..random() % 40 {
            let line = lines.next().unwrap().unwrap();
            reported = line["appended ".len()..].parse().unwrap();
        }
        std::thread::sleep(Duration::from_micros(random() % 3_000));
        child.kill().unwrap();
        child.wait().unwrap();
        for line in lines {
            reported = line.unwrap()["appended ".len()..].parse().unwrap();
        }
        let torn = round >= TORN_FROM;
        let blob_torn = torn && !round.is_multiple_of(2);
        if torn {
            let (dir, extension, reach) = if round.is_multiple_of(2) {
                (dir.path().join("store"), Some("jnl"), JOURNAL_TEAR)
            } else {
                (dir.path().join("blobs"), None, BLOB_TEAR)
            };
            if tear(&dir, extension, reach, round.is_multiple_of(3), &mut random) {
                tore += 1;
            }
        }

        let (store, blobs) = open(dir.path());
        let writer = StorageThread::spawn(store.clone(), Arc::new(NoHooks));
        writer.recovered(AGENT, store.raft(AGENT).unwrap().applied);
        let recovery = recovery_cut(&store, &blobs, AGENT).unwrap();
        smol::block_on(writer.commit(recovery.changes)).unwrap();
        drop(writer);
        let cut = recovery.from;
        let rows = store.raft(AGENT).unwrap();
        let start = rows.log_start.0;
        let held: Vec<u64> = rows.log.iter().map(|(index, _)| *index).collect();
        let last = held.last().copied().unwrap_or(start);
        assert_eq!(
            held,
            (start + 1..=last).collect::<Vec<_>>(),
            "round {round}: the log has a gap"
        );
        for (index, entry) in &rows.log {
            let blob = entry.blobs[0];
            let bytes = blobs.get(&blob.hash).unwrap();
            assert_eq!(
                bytes.as_deref(),
                Some(&blob_bytes(*index)[..]),
                "round {round}: entry {index} lacks its blob"
            );
        }
        // A journal tear reaches the last batch. A blob tear reaches the
        // tail of the newest segment, which may hold an older entry's blob
        // that collection moved there: the log is cut at that entry, and
        // only that cut, from a blob truly gone, may take reported entries.
        let floor = match (torn, cut) {
            (false, _) => reported,
            (true, Some(at)) if blob_torn => reported.min(at - 1),
            (true, _) => reported.saturating_sub(1),
        };
        assert!(
            last >= floor,
            "round {round}: the log ends at {last}, but {reported} was reported durable"
        );
        let how = if torn { "killed and torn" } else { "killed" };
        let cut = cut.map_or(String::new(), |at| format!(", cut at {at}"));
        println!(
            "round {round}: {how} after {reported}; log {}..={last}{cut}",
            start + 1
        );
        drop(blobs);
        drop(store);
    }
    assert!(tore > 0, "no torn round reached data");
    println!("blob_crash: {ROUNDS} rounds kept every entry's blob");
}

/// Tear the newest file under `dir` (with `extension`, if given): truncate
/// its data by up to `most` bytes, or zero up to its last `most` bytes of
/// data. Whether it tore any. Journals are preallocated, so the data ends
/// before the file does.
fn tear(
    dir: &std::path::Path,
    extension: Option<&str>,
    most: u64,
    truncate: bool,
    random: &mut impl FnMut() -> u64,
) -> bool {
    let mut files = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(&path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            let matches = match extension {
                Some(extension) => path.extension().is_some_and(|found| found == extension),
                None => path.extension().is_none(),
            };
            let Some(id) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| stem.parse::<u64>().ok())
            else {
                continue;
            };
            if matches {
                files.push((id, path));
            }
        }
    }
    let Some((_, file)) = files.into_iter().max() else {
        return false;
    };
    let mut bytes = std::fs::read(&file).unwrap();
    let end = bytes
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |at| at + 1);
    if end == 0 {
        return false;
    }
    let reach = 1 + (random() % most.min(end as u64)) as usize;
    if truncate {
        let handle = std::fs::OpenOptions::new().write(true).open(&file).unwrap();
        handle.set_len((end - reach) as u64).unwrap();
    } else {
        bytes[end - reach..end].fill(0);
        std::fs::write(&file, bytes).unwrap();
    }
    true
}
