//! A node killed mid-write recovers its applied index and its state as one
//! prefix of the work results it applied, the child applying them in a
//! loop. A tear of the journal's tail truncates it or zeroes its last
//! bytes as unwritten sectors read, and the store must still recover a
//! prefix, losing at most the batches the tear reached. (A flipped bit
//! inside a complete batch is a different fault: fjall refuses to open
//! rather than guess.)

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::BTreeMap;
use std::path::Path;

use vos_checker::crash::{Round, Rounds, journal, slot_key};
use vos_node::store::{Fjall, LogEntry, PersistMode};
use vos_wire::ids::{AgentId, InstanceId};
use vos_wire::keys;
use vos_wire::result::Write;

const AGENT: AgentId = AgentId(1);
const WRITES: u64 = 200;
const SLOTS: u64 = 5_000;
const ROUNDS: Rounds = Rounds::twelve("VOS_CRASH_WRITER", "", 50);
/// At most this many bytes are torn: less than one work result's batch,
/// so a tear reaches at most the last two.
const TEAR: u64 = 4096;

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
    ROUNDS.run(writer, journal(TEAR), |round| check(round, &mut last));
    println!("crash: {} rounds recovered one prefix each", ROUNDS.rounds);
}

/// The store recovered one prefix, at least through what the writer
/// reported committed, or else through the index `last` recovered at.
fn check(round: Round, last: &mut u64) {
    let reported = round.reported.unwrap_or(*last);
    // A tear reaches at most the last batch on disk, which may be one
    // an earlier round committed.
    let (floor, how) = (round.floor(reported, 1), round.how());
    let Round {
        number: round, dir, ..
    } = round;
    let store = Fjall::open(dir).unwrap();
    let view = store.snapshot();
    let applied = view.applied(AGENT).unwrap().unwrap_or(0);
    assert!(
        applied >= floor,
        "round {round}: applied {applied}, but {reported} was reported committed"
    );
    let state: BTreeMap<_, _> = keys::instance_prefixes(InstanceId(0))
        .iter()
        .flat_map(|prefix| view.scan(AGENT, prefix, None))
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
    println!("round {round}: {how} after {reported}, recovered at {applied}");
    *last = applied;
}
