//! Window cuts killed mid-way, on the checker's crash rounds: a crash
//! between a cut and its proofs loses neither.
//!
//! A child process applies work results as the node does (the agent's
//! apply, and the node's undo rows beside its writes, in one commit), a
//! window boundary every ten versions and a pending request in each
//! window, and every few versions builds as the node's builder does, one
//! build after another, each in small batches of its own commits; so a cut
//! often waits several results for its build, and its build several
//! commits for its last. The test kills it at random moments and reopens
//! the store; later rounds tear the journal's tail first. Some rounds
//! stop between a cut and its proofs: the cut recorded (its version
//! applied) and its pending requests' proofs not yet persisted. After
//! each round, building to the end gives, as if no crash had happened:
//!
//! - every cut at its version: the version before the first result
//!   timed at or past the window's boundary;
//! - the root at each of the two latest cuts, the root from scratch over
//!   the values at the cut;
//! - for each pending request of those windows, its rows as they stood at
//!   the cut, with their salts, and their proof verifying against that
//!   root;
//! - the agent's root at the recovered version, no row off the tree, and
//!   no dirty, seed or undo row left.

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

#[path = "cuts/model.rs"]
mod model;

use std::path::Path;
use std::time::Duration;

use vos_checker::crash::{Round, Rounds, journal};
use vos_node::roots;
use vos_wire::Encode;
use vos_wire::keys;

use model::{AGENT, Entry, History, MAPS, Replica, SPACE, check_proof, cuts, pending, row, undos};

const KEYS: u64 = 2_000;
const WRITES: u64 = 250;
/// A build every this many versions, in batches of `BATCH` keys: a cut,
/// every tenth version, waits up to six results for its build.
const BUILD_EVERY: u64 = 7;
const BATCH: usize = 64;
/// Twelve rounds, the last six tearing the journal before reopening.
const ROUNDS: Rounds = Rounds {
    kill_within: Duration::from_millis(30),
    ..Rounds::twelve("VOS_CUT_CRASH_WRITER", "", 12)
};
/// At most this many bytes of the journal are torn: less than a build's
/// batch, so a tear reaches at most the last apply.
const TEAR: u64 = 4096;

/// Version `version`'s entry: the install first, then a result every
/// 100 ms, so a window of a second is cut at every tenth version, with
/// `WRITES` committed writes, and a request of sixteen rows at the third
/// version of each window.
fn entry(version: u64) -> Entry {
    if version == 1 {
        return Entry::install(100, SPACE);
    }
    let committed = (0..WRITES)
        .map(|index| {
            let slot = (version * 7919 + index * 31) % KEYS;
            let value = (!(version + index).is_multiple_of(9)).then(|| version.encode());
            (
                MAPS[(slot % 2) as usize],
                slot.to_be_bytes().to_vec(),
                value,
            )
        })
        .collect();
    let mut entry = Entry::at(100 * version, committed);
    if version % 10 == 3 {
        let rows = (0..16u64)
            .map(|index| {
                let slot = (version * 13 + index * 97) % (KEYS + 100);
                row(MAPS[(slot % 2) as usize], &slot.to_be_bytes())
            })
            .collect();
        entry.request = Some(pending(version, rows));
    }
    entry
}

/// The model through `version`.
fn history(version: u64) -> History {
    let mut history = History::default();
    for at in 1..=version {
        history.push(entry(at));
    }
    history
}

fn writer(dir: &Path) {
    let replica = Replica::open(dir);
    let mut version = replica.version();
    loop {
        version += 1;
        assert!(replica.apply(version, &entry(version).result(version - 1)));
        println!("{version}");
        if version.is_multiple_of(BUILD_EVERY) {
            replica.build_all(BATCH);
        }
    }
}

fn main() {
    let mut last = 0;
    let mut between = 0;
    ROUNDS.run(writer, journal(TEAR), |round| {
        between += usize::from(check(round, &mut last));
    });
    assert!(
        between > 0,
        "no round was killed between a cut and its proofs"
    );
    println!(
        "cut crash: {} rounds resumed to every cut's root and proofs, {between} of them killed between a cut and its proofs",
        ROUNDS.rounds
    );
}

/// Check a round, and say whether it was killed between a cut and its
/// proofs: a cut recorded with a pending request of its window and no
/// proof of it.
fn check(round: Round, last: &mut u64) -> bool {
    let reported = round.reported.unwrap_or(*last);
    let (floor, how) = (round.floor(reported, 1), round.how());
    let Round {
        number: round, dir, ..
    } = round;
    let replica = Replica::open(dir);
    let version = replica.version();
    assert!(
        version >= floor,
        "round {round}: at {version}, but {reported} was reported applied"
    );
    let history = history(version);
    let before = replica.snapshot();
    assert_eq!(
        cuts(&before),
        history.cuts(version),
        "round {round}: the cuts"
    );
    let requests = history.requests(version);
    let between = requests.iter().any(|(id, (window, _))| {
        cuts(&before).contains_key(window)
            && roots::cut_proof(&before, AGENT, *id).unwrap().is_none()
    });
    drop(before);
    replica.build_all(BATCH);
    let snapshot = replica.snapshot();
    let recorded = cuts(&snapshot);
    assert_eq!(recorded, history.cuts(version), "round {round}: the cuts");
    let latest: Vec<(u64, u64)> = recorded
        .iter()
        .rev()
        .take(2)
        .map(|(w, c)| (*w, *c))
        .collect();
    for (window, cut) in &latest {
        assert_eq!(
            roots::cut_root(&snapshot, AGENT, *window).unwrap(),
            Some((history.root(*cut), *cut)),
            "round {round}: the root at cut({window})"
        );
    }
    for (id, (window, read)) in &requests {
        let Some((_, cut)) = latest.iter().find(|(kept, _)| kept == window) else {
            continue;
        };
        let proof = roots::cut_proof(&snapshot, AGENT, *id)
            .unwrap()
            .unwrap_or_else(|| panic!("round {round}: no proof of {id:?}"));
        check_proof(&history, &proof, *window, *cut, read);
    }
    assert_eq!(
        roots::agent_root(&snapshot, AGENT).unwrap(),
        (history.root(version), version),
        "round {round}: the agent's root"
    );
    assert!(
        roots::rows_match_tree(&snapshot, AGENT).unwrap(),
        "round {round}: rows off the tree"
    );
    assert!(undos(&snapshot).is_empty(), "round {round}: undo rows left");
    for prefix in [keys::dirty_prefix(), keys::seed_prefix()] {
        assert!(
            snapshot.scan(AGENT, &prefix, None).next().is_none(),
            "round {round}: dirty or seed rows left"
        );
    }
    let mid = if between {
        ", between a cut and its proofs"
    } else {
        ""
    };
    println!("round {round}: {how} after {reported}{mid}, resumed at {version}");
    *last = version;
    between
}
