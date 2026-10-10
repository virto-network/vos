//! A node killed mid-write recovers its applied index and its state as one
//! prefix of the work results it applied.
//!
//! The test runs itself as a child process that applies work results in a
//! loop, kills it at a random moment, reopens the store and checks it, for
//! several rounds on one store. A kill leaves the page cache intact, so
//! every commit the child reported survives. Later rounds also tear the
//! journal's tail as a power loss could, truncating it or zeroing its last
//! bytes as unwritten sectors read, and the store must still recover a
//! prefix, losing at most the batches the tear reached. (A flipped bit
//! inside a complete batch is a different fault: fjall refuses to open
//! rather than guess.)
//!
//! The store lives in a temporary directory, which may be tmpfs: the test
//! covers recovery, not the disk's durability.

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use vos_node::store::{Batch, Durability, Fjall, LogEntry, Store, View};
use vos_wire::ids::{AgentId, InstanceId};
use vos_wire::keys;
use vos_wire::result::Write;

const AGENT: AgentId = AgentId(1);
const WRITES: u64 = 200;
const SLOTS: u64 = 5_000;
const ROUNDS: usize = 12;
/// Rounds from this one on tear the journal before reopening.
const TORN_FROM: usize = 6;
/// At most this many bytes are torn: less than one work result's batch,
/// so a tear reaches at most the last two.
const TEAR: u64 = 4096;
const WRITER: &str = "VOS_CRASH_WRITER";

fn slot_key(slot: u64) -> Vec<u8> {
    [
        keys::table_prefix(InstanceId(0), 1),
        slot.to_be_bytes().to_vec(),
    ]
    .concat()
}

/// Work result `index` writes `index` into `WRITES` slots, and deletes one.
fn writes(index: u64) -> Vec<Write> {
    let mut writes: Vec<_> = (0..WRITES)
        .map(|j| Write {
            key: slot_key((index * 7919 + j) % SLOTS),
            value: Some(index.to_be_bytes().to_vec()),
        })
        .collect();
    writes.push(Write {
        key: slot_key((index * 31) % SLOTS),
        value: None,
    });
    writes
}

fn writer(dir: &str) {
    let store = Fjall::open(dir).unwrap();
    let mut index = store.snapshot().applied(AGENT).unwrap().unwrap_or(0);
    loop {
        index += 1;
        let mut batch = store.batch();
        batch.append(
            AGENT,
            index,
            &LogEntry::result(1, index.to_be_bytes().to_vec()),
        );
        batch.apply(AGENT, 0, index, &writes(index));
        let durability = if index.is_multiple_of(2) {
            Durability::Synced
        } else {
            Durability::Buffered
        };
        batch.commit(durability).unwrap();
        println!("{index}");
    }
}

fn expected(applied: u64) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let mut state = BTreeMap::new();
    for index in 1..=applied {
        for write in writes(index) {
            match write.value {
                Some(value) => state.insert(write.key, value),
                None => state.remove(&write.key),
            };
        }
    }
    state
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
    let mut last: u64 = 0;
    let mut tore = 0;
    for round in 0..ROUNDS {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .env(WRITER, dir.path())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        let mut lines = BufReader::new(child.stdout.take().unwrap()).lines();
        let wait = random() % 50;
        let mut reported = last;
        for _ in 0..wait {
            reported = lines.next().unwrap().unwrap().parse().unwrap();
        }
        std::thread::sleep(Duration::from_micros(random() % 3_000));
        child.kill().unwrap();
        child.wait().unwrap();
        // Lines the child printed before it died were committed too.
        for line in lines {
            reported = line.unwrap().parse().unwrap();
        }
        let torn = round >= TORN_FROM;
        if torn && tear(dir.path(), round.is_multiple_of(2), &mut random) {
            tore += 1;
        }

        let store = Fjall::open(dir.path()).unwrap();
        let view = store.snapshot();
        let applied = view.applied(AGENT).unwrap().unwrap_or(0);
        // A tear reaches at most the last batch on disk, which may be one
        // an earlier round committed.
        let floor = if torn {
            reported.saturating_sub(1)
        } else {
            reported
        };
        assert!(
            applied >= floor,
            "round {round}: applied {applied}, but {reported} was reported committed"
        );
        let state: BTreeMap<_, _> = view
            .scan(AGENT, &keys::instance_prefix(InstanceId(0)), None)
            .map(Result::unwrap)
            .collect();
        assert!(
            state == expected(applied),
            "round {round}: the state is not the prefix ending at {applied}"
        );
        assert_eq!(
            store
                .log_entry(AGENT, applied)
                .unwrap()
                .map(|entry| entry.body),
            (applied > 0).then(|| applied.to_be_bytes().to_vec()),
            "round {round}"
        );
        assert_eq!(
            store.log_entry(AGENT, applied + 1).unwrap(),
            None,
            "round {round}"
        );
        let how = if torn { "killed and torn" } else { "killed" };
        println!("round {round}: {how} after {reported}, recovered at {applied}");
        last = applied;
    }
    assert!(tore > 0, "no torn round reached the journal's data");
    println!("crash: {ROUNDS} rounds recovered one prefix each");
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
