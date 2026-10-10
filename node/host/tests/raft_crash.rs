//! A replica's storage killed mid-write recovers a state Raft can trust.
//!
//! A child process drives the node log writer as a replica does: it
//! appends each entry with its hard state, synced; applies it without a
//! sync; moves the commit index without a sync; changes term now and
//! then; and compacts its log below what the writer says is durably
//! applied. The test kills it at random moments, reopens the store and
//! checks, over several rounds on one store, later rounds tearing the
//! journal's tail as a power loss could:
//!
//! - the applied index and the state are one prefix of the applies
//!   (section 9.5, invariant 1);
//! - the log holds every entry from its start through the applied index,
//!   and on to its end with no gap (invariant 2: an apply is never durable
//!   without the append before it);
//! - the log starts at or below the applied index (invariant 4);
//! - the term and every append the child reported synced survive, but for
//!   a tear's reach.
//!
//! The store lives in a temporary directory, which may be tmpfs: the test
//! covers recovery, not the disk's durability.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use vos_node::NoHooks;
use vos_node::storage::{Change, StorageThread};
use vos_node::store::{Fjall, HardState, LogEntry, Store, View};
use vos_wire::ids::{AgentId, InstanceId};
use vos_wire::keys;
use vos_wire::result::Write;

const AGENT: AgentId = AgentId(1);
const WRITES: u64 = 50;
const SLOTS: u64 = 1_000;
const ROUNDS: usize = 12;
/// Rounds from this one on tear the journal before reopening.
const TORN_FROM: usize = 6;
/// At most this many bytes are torn: less than one entry's batches.
const TEAR: u64 = 1024;
const WRITER: &str = "VOS_RAFT_CRASH_WRITER";

fn slot_key(slot: u64) -> Vec<u8> {
    [
        keys::table_prefix(InstanceId(0), 1),
        slot.to_be_bytes().to_vec(),
    ]
    .concat()
}

/// Entry `index` writes `index` into `WRITES` slots.
fn writes(index: u64) -> Vec<Write> {
    (0..WRITES)
        .map(|j| Write {
            key: slot_key((index * 7919 + j) % SLOTS),
            value: Some(index.to_be_bytes().to_vec()),
        })
        .collect()
}

fn expected(applied: u64) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut state = BTreeMap::new();
    for index in 1..=applied {
        for write in writes(index) {
            state.insert(write.key, write.value.expect("a value"));
        }
    }
    state
}

/// The term entry `index` was appended at: a new term every 25 entries.
fn term_of(index: u64) -> u64 {
    1 + index / 25
}

fn writer(dir: &str) {
    let store = Fjall::open(dir).unwrap();
    let rows = store.raft(AGENT).unwrap();
    let writer = StorageThread::spawn(store.clone(), Arc::new(NoHooks));
    writer.recovered(AGENT, rows.applied);
    let mut log_start = rows.log_start.0;
    let last = rows
        .log
        .last()
        .map_or(rows.log_start.0, |(index, _)| *index);
    let mut applied = rows.applied;
    let commit = |changes| smol::block_on(writer.commit(changes)).unwrap();
    // Apply what was appended but not applied before the crash.
    let mut index = last;
    for at in applied + 1..=last {
        commit(vec![Change::Apply {
            agent: AGENT,
            epoch: 0,
            index: at,
            writes: writes(at),
        }]);
        applied = at;
    }
    loop {
        index += 1;
        let term = term_of(index);
        commit(vec![
            Change::Append {
                agent: AGENT,
                index,
                entry: LogEntry::result(term, index.to_be_bytes().to_vec()),
            },
            Change::Hard {
                agent: AGENT,
                hard: HardState {
                    term,
                    vote: Some(1),
                    commit: applied,
                },
                sync: true,
            },
        ]);
        println!("appended {index}");
        commit(vec![Change::Apply {
            agent: AGENT,
            epoch: 0,
            index,
            writes: writes(index),
        }]);
        applied = index;
        if index.is_multiple_of(3) {
            commit(vec![Change::Hard {
                agent: AGENT,
                hard: HardState {
                    term,
                    vote: Some(1),
                    commit: index,
                },
                sync: false,
            }]);
        }
        let durable = writer.durably_applied(AGENT);
        if durable >= log_start + 6 {
            let through = durable - 2;
            commit(vec![Change::Compact {
                agent: AGENT,
                through,
                term: term_of(through),
                membership: None,
            }]);
            log_start = through;
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
        for _ in 0..random() % 60 {
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
        if torn && tear(dir.path(), round.is_multiple_of(2), &mut random) {
            tore += 1;
        }

        let store = Fjall::open(dir.path()).unwrap();
        let rows = store.raft(AGENT).unwrap();
        let applied = store.snapshot().applied(AGENT).unwrap().unwrap_or(0);
        assert_eq!(rows.applied, applied);
        // Invariant 1: one prefix.
        let state: BTreeMap<_, _> = store
            .snapshot()
            .scan(AGENT, &keys::instance_prefix(InstanceId(0)), None)
            .map(Result::unwrap)
            .collect();
        assert!(
            state == expected(applied),
            "round {round}: the state is not the prefix ending at {applied}"
        );
        // Invariant 4: the log starts at or below the applied index.
        assert!(
            rows.log_start.0 <= applied,
            "round {round}: the log starts at {} past applied {applied}",
            rows.log_start.0
        );
        // Invariant 2: the log holds every entry from its start, through
        // the applied index, with no gap.
        let held: Vec<u64> = rows.log.iter().map(|(index, _)| *index).collect();
        let last = held.last().copied().unwrap_or(rows.log_start.0);
        assert_eq!(
            held,
            (rows.log_start.0 + 1..=last).collect::<Vec<_>>(),
            "round {round}: the log has a gap"
        );
        assert!(
            last >= applied,
            "round {round}: applied {applied} past the log's end {last}"
        );
        for (index, entry) in &rows.log {
            assert_eq!(entry.term, term_of(*index), "round {round}: entry {index}");
            assert_eq!(entry.body, index.to_be_bytes().to_vec());
        }
        // Synced appends and terms survive, but for a tear's reach.
        let floor = if torn {
            reported.saturating_sub(1)
        } else {
            reported
        };
        assert!(
            last >= floor,
            "round {round}: the log ends at {last}, but {reported} was reported synced"
        );
        assert!(
            rows.hard.term >= term_of(floor),
            "round {round}: term {} after {reported} was reported",
            rows.hard.term
        );
        let how = if torn { "killed and torn" } else { "killed" };
        println!(
            "round {round}: {how} after {reported}; log {}..={last}, applied {applied}",
            rows.log_start.0 + 1
        );
    }
    assert!(tore > 0, "no torn round reached the journal's data");
    println!("raft_crash: {ROUNDS} rounds recovered a state Raft can trust");
}

/// Truncate the newest journal's data by up to [`TEAR`] bytes, or zero up
/// to its last [`TEAR`] bytes of data: whether it tore any. fjall
/// preallocates its journals, so the data ends before the file does.
fn tear(dir: &std::path::Path, truncate: bool, random: &mut impl FnMut() -> u64) -> bool {
    let mut journals = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(path) = pending.pop() {
        for entry in std::fs::read_dir(&path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "jnl") {
                let id: u64 = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .and_then(|stem| stem.parse().ok())
                    .unwrap_or(0);
                journals.push((id, path));
            }
        }
    }
    let (_, journal) = journals.into_iter().max().expect("a journal");
    let mut bytes = std::fs::read(&journal).unwrap();
    let end = bytes
        .iter()
        .rposition(|&byte| byte != 0)
        .map_or(0, |at| at + 1);
    if end == 0 {
        return false;
    }
    let reach = 1 + (random() % TEAR.min(end as u64)) as usize;
    if truncate {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .open(&journal)
            .unwrap();
        file.set_len((end - reach) as u64).unwrap();
    } else {
        bytes[end - reach..end].fill(0);
        std::fs::write(&journal, bytes).unwrap();
    }
    true
}
