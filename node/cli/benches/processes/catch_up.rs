//! A follower's catch-up after it was down while its agent's leader
//! committed large results, each batch's a few fills of about 240 KB,
//! kept as blobs their entries name, on the node's default log settings
//! (`vos_node::Config`'s `compact_*`, printed with the row):
//! - **within the tail:** down while the leader commits less than the tail
//!   it keeps, it is sent the entries and fetches their blobs;
//! - **beyond the tail:** down until the leader compacted past its last
//!   entry, it takes a snapshot.
//!
//! Each gives, from the follower's restart, when it listens, names its
//! leader, first applies past where it stopped, and has applied the
//! leader's commit; and the bytes loopback carried meanwhile (every
//! process's on the machine). Then the rows a snapshot of the agent
//! carries, read from the follower's store once it is killed.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use vos_node::client::Client;
use vos_wire::Encode;
use vos_wire::ids::AgentId;
use vos_wire::ingress::{ReplicaStatus, Response};
use vos_wire::result::Outcome;

use crate::load::Signed;
use crate::nodes::{Process, Space};
use crate::{COUNTER, NODES};

/// Rows each fill writes, of [`ROW`] bytes: its result is large alone.
const ROWS: u32 = 4;
const ROW: u32 = 60_000;
/// Sessions filling at once: batches of a few fills.
const FILLERS: u8 = 8;
/// Fills while the follower is down within the tail: about 7.7 MB of
/// results, under the tail's bytes and entries.
const WITHIN: u64 = 32;
/// The longest a wait here takes.
const WAIT: Duration = Duration::from_secs(120);

pub fn catch_up(space: &Space, signed: &Signed) {
    let defaults = vos_node::Config::new(Vec::new());
    println!(
        "catch-up: a log compacted once {} entries or {} MiB past its start are applied durably, keeping at most {} entries and {} MiB below; snapshot chunks of {} KiB",
        defaults.compact_every,
        defaults.compact_bytes >> 20,
        defaults.compact_tail,
        defaults.compact_tail_bytes >> 20,
        defaults.snapshot_chunk >> 10,
    );
    let agent = signed.agent;
    let leader = space.leader(agent);
    let follower = &space.processes[(leader + 1) % NODES];
    fill(space, signed, leader, |answered| answered >= 16);
    for beyond in [false, true] {
        let commit = settled(space, agent);
        let before = status(follower, agent).expect("the follower's replica");
        follower.kill();
        let calls = fill(space, signed, leader, |answered| {
            if beyond {
                status(&space.processes[leader], agent)
                    .is_some_and(|status| status.log_start > before.last_index)
            } else {
                answered >= WITHIN
            }
        });
        let at = status(&space.processes[leader], agent).expect("the leader's replica");
        let carried = loopback();
        let started = Instant::now();
        let listens = follower.restart();
        // When it first names its leader, and first applies past where it
        // stopped: an entry, or a snapshot.
        let (mut knows, mut moves) = (None, None);
        let caught = wait(|| {
            let status = status(follower, agent)?;
            let now = started.elapsed();
            if status.leader.is_some() {
                knows.get_or_insert(now);
            }
            if status.applied > before.applied {
                moves.get_or_insert(now);
            }
            (status.applied >= at.commit).then_some(status)
        });
        let took = started.elapsed();
        let carried = loopback() - carried;
        let seconds = |at: Option<Duration>| at.unwrap_or(took).as_secs_f64();
        let how = if caught.log_start > before.last_index {
            format!("from a snapshot at {}", caught.log_start)
        } else {
            "from the log".to_string()
        };
        println!(
            "catch-up {}: down while {calls} fills, about {:.1} MB of results, were committed in {} entries (the leader's log {}..={}); restarted, it listens in {:.2} s, names its leader at {:.2} s, first applies at {:.2} s and has applied the leader's commit at {:.2} s, {how}; loopback carried {:.1} MB meanwhile",
            if beyond {
                "beyond the tail"
            } else {
                "within the tail"
            },
            (calls * u64::from(ROWS * ROW)) as f64 / 1e6,
            at.commit - commit,
            at.log_start + 1,
            at.last_index,
            listens.as_secs_f64(),
            seconds(knows),
            seconds(moves),
            took.as_secs_f64(),
            carried as f64 / 1e6,
        );
    }
    // What a snapshot of the agent carries: its rows as an export streams
    // them, read where the last one was installed.
    follower.kill();
    let store = follower.store();
    let mut export = store.export(agent).unwrap();
    let (mut rows, mut bytes) = (0, 0);
    while let Some(chunk) = export.next_chunk(defaults.snapshot_chunk).unwrap() {
        rows += chunk.len();
        bytes += chunk
            .iter()
            .map(|(key, value)| key.len() + value.len())
            .sum::<usize>();
    }
    println!(
        "catch-up: the agent's snapshot carries {rows} rows, {:.2} MB",
        bytes as f64 / 1e6
    );
}

/// Fill `signed`'s agent from [`FILLERS`] sessions at once, at node `at`,
/// until `done` says so of the fills answered: how many were.
fn fill(space: &Space, signed: &Signed, at: usize, done: impl Fn(u64) -> bool) -> u64 {
    let answered = AtomicU64::new(0);
    let stop = AtomicBool::new(false);
    let arguments = (ROWS, ROW).encode();
    std::thread::scope(|scope| {
        for filler in 0..FILLERS {
            let (answered, stop, arguments) = (&answered, &stop, &arguments);
            scope.spawn(move || {
                let key = SigningKey::from_bytes(&[0x40 + filler; 32]);
                let mut client = Client::new(&space.processes[at].target, key);
                while !stop.load(Ordering::Relaxed) {
                    match client.call(signed.agent, COUNTER, signed.fill, arguments) {
                        Ok(Response::Ran {
                            outcome: Outcome::Done(_),
                            ..
                        }) => answered.fetch_add(1, Ordering::Relaxed),
                        other => panic!("a fill: {other:?}"),
                    };
                }
            });
        }
        let until = Instant::now() + WAIT;
        while !done(answered.load(Ordering::Relaxed)) {
            assert!(Instant::now() < until, "the fills did not end");
            std::thread::sleep(Duration::from_millis(20));
        }
        stop.store(true, Ordering::Relaxed);
    });
    answered.into_inner()
}

/// `agent`'s replica on `process`, if it answers.
fn status(process: &Process, agent: AgentId) -> Option<ReplicaStatus> {
    match process.operator().status(agent) {
        Ok(Response::Status(status)) => Some(status),
        _ => None,
    }
}

/// Wait until every replica of `agent` applied its leader's commit: that
/// commit.
fn settled(space: &Space, agent: AgentId) -> u64 {
    let commit = status(&space.processes[space.leader(agent)], agent)
        .expect("the leader's replica")
        .commit;
    wait(|| {
        space
            .processes
            .iter()
            .all(|process| status(process, agent).is_some_and(|status| status.applied >= commit))
            .then_some(commit)
    })
}

/// What `ready` gives once it does, asked every 5 ms for at most [`WAIT`].
fn wait<T>(mut ready: impl FnMut() -> Option<T>) -> T {
    let until = Instant::now() + WAIT;
    loop {
        if let Some(value) = ready() {
            return value;
        }
        assert!(Instant::now() < until, "not ready within {WAIT:?}");
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// The bytes the loopback interface received so far, every process's.
fn loopback() -> u64 {
    std::fs::read_to_string("/proc/net/dev")
        .unwrap_or_default()
        .lines()
        .find_map(|line| line.trim_start().strip_prefix("lo:"))
        .and_then(|fields| fields.split_whitespace().next()?.parse().ok())
        .unwrap_or(0)
}
