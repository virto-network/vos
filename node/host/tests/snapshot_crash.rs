//! Snapshot installs killed mid-way: an agent's state is always exactly one
//! installed snapshot, plus the applies after it, at the applied index
//! recorded with it (section 9.5, invariant 6).
//!
//! A child process installs snapshots of known content in a loop, as a
//! replica does: it clears the next epoch, stages the snapshot's rows
//! there in chunks without a sync, switches to it in one synced batch,
//! applies a few entries, and drops the old epoch in chunks. On start it
//! sweeps epochs a crash left behind. The test kills it at random moments
//! and reopens the store; later rounds tear the journal's tail first.
//! After each:
//!
//! - the agent's rows are exactly snapshot `S` (every key at `S`) with the
//!   applies after it, where `S` is the applied index rounded down to a
//!   snapshot's;
//! - no staged row of an unfinished install is visible;
//! - every install reported survives, but for a tear's reach.

/// The allocator the node's binary runs on.
#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use vos_node::NoHooks;
use vos_node::storage::{Change, StorageThread};
use vos_node::store::{Fjall, HardState, Membership, Store, Switch, View, next_epoch};
use vos_wire::ids::{AgentId, InstanceId};
use vos_wire::keys;
use vos_wire::result::Write;

const AGENT: AgentId = AgentId(1);
const KEYS: u64 = 600;
/// Snapshots are at multiples of this; applies follow each.
const EVERY: u64 = 10;
const APPLIES: u64 = 3;
const CHUNK: usize = 100;
const ROUNDS: usize = 12;
const TORN_FROM: usize = 6;
/// At most this many bytes of the journal are torn: about one batch.
const TEAR: u64 = 64;
const WRITER: &str = "VOS_SNAPSHOT_CRASH_WRITER";

fn key(slot: u64) -> Vec<u8> {
    [
        keys::table_prefix(InstanceId(0), 1),
        slot.to_be_bytes().to_vec(),
    ]
    .concat()
}

/// The keys snapshot `at` holds: a window that moves with `at`, so a row
/// an install leaked (left staged, or not dropped) would show.
fn slots(at: u64) -> std::ops::Range<u64> {
    let first = (at / EVERY * 37) % KEYS;
    first..first + KEYS
}

/// Snapshot `at`'s rows: every key of its window holds `at`.
fn snapshot(at: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
    slots(at)
        .map(|slot| (key(slot), at.to_be_bytes().to_vec()))
        .collect()
}

/// The apply at `index` writes `index` into one key of its snapshot's
/// window.
fn apply_writes(index: u64) -> Vec<Write> {
    let window = slots(index - index % EVERY);
    vec![Write {
        key: key(window.start + index % KEYS),
        value: Some(index.to_be_bytes().to_vec()),
    }]
}

/// The agent's rows at applied index `applied`.
fn expected(applied: u64) -> BTreeMap<Vec<u8>, Vec<u8>> {
    let base = applied - applied % EVERY;
    let mut rows: BTreeMap<_, _> = if base == 0 {
        BTreeMap::new()
    } else {
        snapshot(base).into_iter().collect()
    };
    for index in base + 1..=applied {
        for write in apply_writes(index) {
            rows.insert(write.key, write.value.expect("a value"));
        }
    }
    rows
}

fn writer(dir: &str) {
    let store = Fjall::open(dir).unwrap();
    let writer = StorageThread::spawn(store.clone(), Arc::new(NoHooks));
    let commit = |change| smol::block_on(writer.commit(vec![change])).unwrap();
    let drop_epoch = |epoch| {
        commit(Change::DropEpoch {
            agent: AGENT,
            epoch,
            limit: usize::MAX,
        })
    };
    // Epochs a crash left: an unfinished install's, or an old one.
    for epoch in store.stale_epochs(AGENT).unwrap() {
        drop_epoch(epoch);
    }
    let view = store.snapshot();
    let mut applied = view.applied(AGENT).unwrap().unwrap_or(0);
    let mut epoch = view.epoch(AGENT).unwrap();
    loop {
        // Finish this snapshot's applies, then install the next one.
        while applied % EVERY < APPLIES && applied > 0 {
            applied += 1;
            commit(Change::Apply {
                agent: AGENT,
                epoch,
                index: applied,
                writes: apply_writes(applied),
            });
        }
        let at = (applied / EVERY + 1) * EVERY;
        let next = next_epoch(epoch);
        drop_epoch(next);
        for (chunk, rows) in snapshot(at).chunks(CHUNK).enumerate() {
            commit(Change::Stage {
                agent: AGENT,
                epoch: next,
                first: chunk == 0,
                rows: rows.to_vec(),
            });
        }
        commit(Change::Switch {
            agent: AGENT,
            switch: Switch {
                epoch: next,
                index: at,
                term: 1,
                hard: HardState {
                    term: 1,
                    vote: None,
                    commit: at,
                },
                membership: Membership::default(),
                log_start_membership: None,
                truncate_after: None,
            },
        });
        println!("installed {at}");
        for _ in 0..KEYS as usize / CHUNK + 1 {
            commit(Change::DropEpoch {
                agent: AGENT,
                epoch,
                limit: CHUNK,
            });
        }
        epoch = next;
        applied = at;
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
        for _ in 0..random() % 6 {
            let line = lines.next().unwrap().unwrap();
            reported = line["installed ".len()..].parse().unwrap();
        }
        std::thread::sleep(Duration::from_micros(random() % 20_000));
        child.kill().unwrap();
        child.wait().unwrap();
        for line in lines {
            reported = line.unwrap()["installed ".len()..].parse().unwrap();
        }
        let torn = round >= TORN_FROM;
        if torn && tear(dir.path(), round.is_multiple_of(2), &mut random) {
            tore += 1;
        }

        let store = Fjall::open(dir.path()).unwrap();
        let view = store.snapshot();
        let applied = view.applied(AGENT).unwrap().unwrap_or(0);
        let rows: BTreeMap<_, _> = view
            .scan(AGENT, &keys::instance_prefix(InstanceId(0)), None)
            .map(Result::unwrap)
            .collect();
        assert!(
            rows == expected(applied),
            "round {round}: the rows are not snapshot {} with applies through {applied}",
            applied - applied % EVERY
        );
        let floor = if torn {
            reported.saturating_sub(EVERY)
        } else {
            reported
        };
        assert!(
            applied >= floor,
            "round {round}: applied {applied}, but {reported} was reported installed"
        );
        let how = if torn { "killed and torn" } else { "killed" };
        println!(
            "round {round}: {how} after {reported}; at {applied} in epoch {}, stale {:?}",
            view.epoch(AGENT).unwrap(),
            store.stale_epochs(AGENT).unwrap()
        );
    }
    assert!(tore > 0, "no torn round reached the journal's data");
    println!("snapshot_crash: {ROUNDS} rounds held one snapshot each");
}

/// Truncate the newest journal's data by up to [`TEAR`] bytes, or zero up
/// to its last [`TEAR`] bytes of data: whether it tore any.
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
