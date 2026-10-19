//! Snapshot installs killed mid-way: an agent's state is always exactly one
//! installed snapshot, plus the applies after it, at the applied index
//! recorded with it.
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

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use vos_checker::crash::{Round, Rounds, journal, slot_key};
use vos_node::NoHooks;
use vos_node::storage::{Change, StorageThread};
use vos_node::store::{Fjall, HardState, Membership, Switch, next_epoch};
use vos_wire::ids::{AgentId, InstanceId};
use vos_wire::keys;
use vos_wire::result::Write;

const AGENT: AgentId = AgentId(1);
const KEYS: u64 = 600;
/// Snapshots are at multiples of this; applies follow each.
const EVERY: u64 = 10;
const APPLIES: u64 = 3;
const CHUNK: usize = 100;
/// Twelve rounds, the last six tearing the journal before reopening.
const ROUNDS: Rounds = Rounds {
    kill_within: Duration::from_millis(20),
    ..Rounds::twelve("VOS_SNAPSHOT_CRASH_WRITER", "installed ", 6)
};
/// At most this many bytes of the journal are torn: about one batch.
const TEAR: u64 = 64;

/// The keys snapshot `at` holds: a window that moves with `at`, so a row
/// an install leaked (left staged, or not dropped) would show.
fn slots(at: u64) -> std::ops::Range<u64> {
    let first = (at / EVERY * 37) % KEYS;
    first..first + KEYS
}

/// Snapshot `at`'s rows: every key of its window holds `at`.
fn snapshot(at: u64) -> Vec<(Vec<u8>, Vec<u8>)> {
    slots(at)
        .map(|slot| (slot_key(slot), at.to_be_bytes().to_vec()))
        .collect()
}

/// The apply at `index` writes `index` into one key of its snapshot's
/// window.
fn apply_writes(index: u64) -> Vec<Write> {
    let window = slots(index - index % EVERY);
    vec![Write {
        key: slot_key(window.start + index % KEYS),
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

fn writer(dir: &Path) {
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
    ROUNDS.run(writer, journal(TEAR), check);
    println!(
        "snapshot_crash: {} rounds held one snapshot each",
        ROUNDS.rounds
    );
}

fn check(round: Round) {
    let reported = round.reported.unwrap_or(0);
    let (floor, how) = (round.floor(reported, EVERY), round.how());
    let Round {
        number: round, dir, ..
    } = round;
    let store = Fjall::open(dir).unwrap();
    let view = store.snapshot();
    let applied = view.applied(AGENT).unwrap().unwrap_or(0);
    let rows: BTreeMap<_, _> = keys::instance_prefixes(InstanceId(0))
        .iter()
        .flat_map(|prefix| view.scan(AGENT, prefix, None))
        .map(Result::unwrap)
        .collect();
    assert!(
        rows == expected(applied),
        "round {round}: the rows are not snapshot {} with applies through {applied}",
        applied - applied % EVERY
    );
    assert!(
        applied >= floor,
        "round {round}: applied {applied}, but {reported} was reported installed"
    );
    println!(
        "round {round}: {how} after {reported}; at {applied} in epoch {}, stale {:?}",
        view.epoch(AGENT).unwrap(),
        store.stale_epochs(AGENT).unwrap()
    );
}
