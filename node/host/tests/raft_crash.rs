//! A replica's storage killed mid-write recovers a state Raft can trust.
//!
//! The child drives the node log writer as a replica does: it appends each
//! entry with its hard state, synced; applies it without a sync; moves the
//! commit index without a sync; changes term now and then; and compacts
//! its log below what the writer says is durably applied. What reopens:
//!
//! - the applied index and the state are one prefix of the applies;
//! - the log starts at or below the applied index;
//! - the log holds every entry from its start through the applied index,
//!   and on to its end with no gap: an apply is never durable without the
//!   append before it;
//! - the term and every append the child reported synced survive, but for
//!   a tear's reach.

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;

use vos_checker::crash::{Round, Rounds, journal, slot_key};
use vos_node::NoHooks;
use vos_node::storage::{Change, StorageThread};
use vos_node::store::{Fjall, HardState, LogEntry};
use vos_wire::ids::{AgentId, InstanceId};
use vos_wire::keys;
use vos_wire::result::Write;

const AGENT: AgentId = AgentId(1);
const WRITES: u64 = 50;
const SLOTS: u64 = 1_000;
const ROUNDS: Rounds = Rounds::twelve("VOS_RAFT_CRASH_WRITER", "appended ", 60);
/// At most this many bytes are torn: less than one entry's batches.
const TEAR: u64 = 1024;

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

fn writer(dir: &Path) {
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
    ROUNDS.run(writer, journal(TEAR), check);
    println!(
        "raft_crash: {} rounds recovered a state Raft can trust",
        ROUNDS.rounds
    );
}

fn check(round: Round) {
    let reported = round.reported.unwrap_or(0);
    let (floor, how) = (round.floor(reported, 1), round.how());
    let Round {
        number: round, dir, ..
    } = round;
    let store = Fjall::open(dir).unwrap();
    let rows = store.raft(AGENT).unwrap();
    let applied = store.snapshot().applied(AGENT).unwrap().unwrap_or(0);
    assert_eq!(rows.applied, applied);
    // One prefix.
    let state: BTreeMap<_, _> = store
        .snapshot()
        .scan(AGENT, &keys::instance_prefix(InstanceId(0)), None)
        .map(Result::unwrap)
        .collect();
    assert!(
        state == expected(applied),
        "round {round}: the state is not the prefix ending at {applied}"
    );
    // The log starts at or below the applied index.
    assert!(
        rows.log_start.0 <= applied,
        "round {round}: the log starts at {} past applied {applied}",
        rows.log_start.0
    );
    // The log holds every entry from its start, through
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
    assert!(
        last >= floor,
        "round {round}: the log ends at {last}, but {reported} was reported synced"
    );
    // Nothing reported synced owes no term.
    let owed = if floor == 0 { 0 } else { term_of(floor) };
    assert!(
        rows.hard.term >= owed,
        "round {round}: term {} after {reported} was reported",
        rows.hard.term
    );
    println!(
        "round {round}: {how} after {reported}; log {}..={last}, applied {applied}",
        rows.log_start.0 + 1
    );
}
