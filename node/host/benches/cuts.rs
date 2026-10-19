//! Window cuts' costs through the node's store and root builder, the
//! plan's two gates for them:
//!
//! - **a committed write with a cut pending:** the node's apply of a
//!   result's committed writes, its undo rows read and written beside
//!   them ([`roots::undo`]), against the same writes with no cut pending.
//!   Gate: accumulate's 1.05 µs on the JIT (slice 4) plus the store's
//!   path with a cut pending, at most twice the 4.3 µs a committed write
//!   costs with none. The ratio to the bench's own cost with no cut
//!   pending is printed beside it;
//! - **a cut's build and its proofs:** from the commit that records a cut
//!   to the commit that marks it built, the build of the writes since the
//!   last complete build and the proofs of 100 pending requests of 16 rows
//!   each. Gate: at most 1 s on a 1M-row agent. Its proofs' part,
//!   generated again from the tree at the cut, is printed apart.
//!
//! `cargo bench -p vos-node --bench cuts -- <keys> [writes]`: a map of
//! `keys` keys (1,000,000), built; `writes` committed writes (10,000, the
//! most one build batch takes, the backlog a builder keeping up holds at a
//! cut) applied before the cut and built by it.

use std::time::{Duration, Instant};

use vos_checker::Random;
use vos_node::roots;
use vos_wire::Encode;

#[path = "../tests/cuts/model.rs"]
mod model;
mod support;

use model::{AGENT, CLOCK, Committed, Entry, MAPS, Replica, SPACE, pending, row};
use support::us;

/// Committed writes per result.
const PER_RESULT: u64 = 1_000;
/// The pending requests a cut proves, and the rows each reads.
const REQUESTS: u64 = 100;
const ROWS: u64 = 16;
/// The plan's gates.
const WRITE_GATE_US: f64 = 2.0 * 4.3;
const ACCUMULATE_US: f64 = 1.05;
const CUT_GATE: Duration = Duration::from_secs(1);

/// `count` committed writes of random keys among `keys`, each a value.
fn random(rng: &mut Random, keys: u64, count: u64, value: u64) -> Vec<Committed> {
    (0..count)
        .map(|_| {
            let slot = rng.draw() % keys;
            (
                MAPS[(slot % 2) as usize],
                slot.to_be_bytes().to_vec(),
                Some(value.encode()),
            )
        })
        .collect()
}

/// The bench's agent: its replica, its next log index, and the time of its
/// latest result.
struct Agent {
    replica: Replica,
    index: u64,
    time: u64,
}

impl Agent {
    /// Apply `entry` as the node does; the time the node's part took, its
    /// undo rows and the commit, and how many undo rows it wrote.
    fn apply(&mut self, entry: &Entry) -> (Duration, usize) {
        self.index += 1;
        self.time = entry.time;
        let version = self.replica.version();
        let (snapshot, mut writes, applied) = self.replica.accumulate(&entry.result(version));
        assert!(applied);
        let started = Instant::now();
        let undo = roots::undo(&snapshot, AGENT, &writes).unwrap();
        let count = undo.len();
        writes.extend(undo);
        self.replica.commit(self.index, writes);
        (started.elapsed(), count)
    }
}

fn main() {
    let args = support::args();
    let keys: u64 = args.first().map_or(1_000_000, |keys| keys.parse().unwrap());
    let before_cut: u64 = args.get(1).map_or(10_000, |writes| writes.parse().unwrap());
    let dir = support::data_dir("cuts-bench");
    let mut agent = Agent {
        replica: Replica::open(&dir),
        index: 0,
        time: CLOCK.origin_ms + 1,
    };
    let mut rng = Random(0x2545_f491_4f6c_dd1d);

    // The map, loaded in results of 10,000 writes within window 0, then
    // built.
    agent.apply(&Entry::install(agent.time, SPACE));
    let all: Vec<u64> = (0..keys).collect();
    for chunk in all.chunks(10_000) {
        let writes = chunk
            .iter()
            .map(|slot| {
                (
                    MAPS[(slot % 2) as usize],
                    slot.to_be_bytes().to_vec(),
                    Some(slot.encode()),
                )
            })
            .collect();
        agent.apply(&Entry::at(agent.time, writes));
    }
    agent.replica.build_all(10_000);
    agent.replica.store.compact().unwrap();

    // The apply path with no cut pending: results of random writes in
    // window 0, no build running, as the pending phase's.
    let rounds = 100u64;
    let mut took = [Duration::ZERO; 2];
    for round in 0..rounds {
        let entry = Entry::at(agent.time, random(&mut rng, keys, PER_RESULT, round));
        let (elapsed, undone) = agent.apply(&entry);
        assert_eq!(undone, 0, "no undo row with no cut pending");
        took[0] += elapsed;
    }
    agent.replica.build_all(10_000);
    agent.replica.store.compact().unwrap();
    // Then with a cut pending: a result crossing B_0 records cut(0), and
    // no build runs while the later results apply, so each rewrite of a
    // row written before the cut keeps an undo row.
    let crossing = CLOCK.boundary(0).unwrap();
    agent.apply(&Entry::at(crossing, Vec::new()));
    let mut undone = 0;
    for round in 0..rounds {
        let entry = Entry::at(crossing, random(&mut rng, keys, PER_RESULT, round));
        let (elapsed, count) = agent.apply(&entry);
        took[1] += elapsed;
        undone += count;
    }
    let (none, pending_cut) = (
        us(took[0], rounds * PER_RESULT),
        us(took[1], rounds * PER_RESULT),
    );
    let with_cut = ACCUMULATE_US + pending_cut;
    println!(
        "apply path: a committed write {none:.2} µs with no cut pending, {pending_cut:.2} µs with one ({undone} undo rows, {:.2}×); \
         with accumulate's {ACCUMULATE_US} µs, {with_cut:.2} µs against the gate of {WRITE_GATE_US:.1} µs: {}",
        pending_cut / none,
        if with_cut <= WRITE_GATE_US {
            "within"
        } else {
            "OVER"
        }
    );
    agent.replica.build_all(10_000);

    // A cut's build and its proofs: `before_cut` writes and 100 requests of
    // 16 rows in window 1, unbuilt, then the result crossing B_1, and the
    // builds to the cut's.
    let window = 1;
    let mut written = 0;
    let mut asked = 0;
    while written < before_cut || asked < REQUESTS {
        let count = PER_RESULT.min(before_cut.saturating_sub(written));
        let mut entry = Entry::at(agent.time, random(&mut rng, keys, count, written));
        written += count;
        if asked < REQUESTS {
            let rows = (0..ROWS)
                .map(|_| {
                    let slot = rng.draw() % (keys + keys / 8);
                    row(MAPS[(slot % 2) as usize], &slot.to_be_bytes())
                })
                .collect();
            entry.request = Some(pending(1_000 + asked, rows));
            asked += 1;
        }
        agent.apply(&entry);
    }
    let crossing = CLOCK.boundary(window).unwrap();
    let started = Instant::now();
    agent.apply(&Entry::at(crossing, Vec::new()));
    let mut builds = 0;
    while roots::cut_root(&agent.replica.snapshot(), AGENT, window)
        .unwrap()
        .is_none()
    {
        agent.replica.build(10_000).expect("a build of the cut");
        builds += 1;
    }
    let took = started.elapsed();
    // The proofs alone: each request's leaves and proof off the tree at
    // the cut, which no build has moved since.
    let snapshot = agent.replica.snapshot();
    let tree = roots::AgentStore::open(&snapshot, AGENT).unwrap();
    let proving = Instant::now();
    for (_, (_, read)) in model::requests(&snapshot) {
        for row in &read.rows {
            vos_tree::NodeStore::leaf(&tree, row).unwrap();
        }
        vos_tree::BatchProof::generate(&tree, &read.rows).unwrap();
    }
    println!(
        "the proofs alone, generated again from the tree at the cut: {:.1} ms",
        proving.elapsed().as_secs_f64() * 1e3
    );
    println!(
        "a cut's build and {REQUESTS} proofs of {ROWS} rows on {keys} keys, {before_cut} writes before it: {:.0} ms in {builds} builds, against the gate of {} ms: {}",
        took.as_secs_f64() * 1e3,
        CUT_GATE.as_millis(),
        if took <= CUT_GATE { "within" } else { "OVER" }
    );
    drop(agent);
    std::fs::remove_dir_all(&dir).ok();
}
