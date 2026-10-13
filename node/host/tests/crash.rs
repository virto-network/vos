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

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Duration;

use vos_checker::crash::{Round, Rounds, tear};
use vos_node::store::{Fjall, LogEntry, PersistMode};
use vos_wire::ids::{AgentId, InstanceId};
use vos_wire::keys;
use vos_wire::result::Write;

const AGENT: AgentId = AgentId(1);
const WRITES: u64 = 200;
const SLOTS: u64 = 5_000;
/// Twelve rounds, the last six tearing the journal before reopening.
const ROUNDS: Rounds = Rounds {
    writer: "VOS_CRASH_WRITER",
    rounds: 12,
    torn_from: 6,
    report: "",
    reports: 50,
    kill_within: Duration::from_millis(3),
};
/// At most this many bytes are torn: less than one work result's batch,
/// so a tear reaches at most the last two.
const TEAR: u64 = 4096;

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

fn writer(dir: &Path) {
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
            PersistMode::SyncAll
        } else {
            PersistMode::Buffer
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
    let mut last = 0;
    ROUNDS.run(
        writer,
        |round, dir, random| tear(dir, Some("jnl"), TEAR, round.is_multiple_of(2), random),
        |round| check(round, &mut last),
    );
    println!("crash: {} rounds recovered one prefix each", ROUNDS.rounds);
}

/// The store recovered one prefix, at least through what the writer
/// reported committed, or else through the index `last` recovered at.
fn check(round: Round, last: &mut u64) {
    let Round {
        number: round,
        dir,
        reported,
        torn,
    } = round;
    let reported = reported.unwrap_or(*last);
    let store = Fjall::open(dir).unwrap();
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
    *last = applied;
}
