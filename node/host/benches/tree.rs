//! A committed map's costs through the node's store and root builder: the
//! apply path's committed write (its value row and dirty row, as accumulate
//! leaves them, through the writer) beside a table write, a build from
//! scratch, and the builder keeping up with applies of committed writes at
//! a sustained rate. Accumulate's own time per write is the testkit's
//! `batch` bench's.
//!
//! `tree-bench <keys> [rate] [seconds]`: a map of `keys` keys, then writes
//! at `rate` committed writes a second (20,000) for `seconds` (30) while the
//! builder runs as the node's does, one build after another at the latest
//! version. Data goes under `target/`: on the reference laptop `/tmp` is
//! tmpfs.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use vos_checker::Random;
use vos_node::NoHooks;
use vos_node::roots::{self, Build};
use vos_node::storage::{Change, StorageThread};
use vos_node::store::Fjall;
use vos_tree::{Blake2b, Hasher};
use vos_wire::Encode;
use vos_wire::ids::{AgentId, InstanceId, MapId};
use vos_wire::keys::{self, Transform};
use vos_wire::records::{stored, versioned};
use vos_wire::result::Write;

mod support;

use support::us;

const AGENT: AgentId = AgentId(7);
const MAP: MapId = MapId {
    instance: InstanceId(1),
    tag: 1,
    transform: Transform::Hashed,
};
/// Committed writes per work result.
const PER_RESULT: u64 = 1_000;

fn seed(version: u64) -> [u8; 32] {
    Blake2b.hash(b"tree bench seed", &[&version.to_le_bytes()])
}

/// A work result's rows, as accumulate leaves them: each committed write's
/// value row and dirty row (or, `committed` false, a table row alone), the
/// seed and the version.
fn rows(version: u64, keys: &[u64], committed: bool) -> Vec<Write> {
    let value = [0xa5u8; 32];
    let mut rows = Vec::with_capacity(2 * keys.len() + 2);
    for key in keys {
        let key = MAP.transform.apply(&key.to_be_bytes());
        if committed {
            rows.push(Write {
                key: keys::committed(&MAP, &key),
                value: Some(stored(&versioned(version, &value))),
            });
            rows.push(Write {
                key: keys::dirty(version, &MAP, &key),
                value: Some(stored(&[])),
            });
        } else {
            rows.push(Write {
                key: [keys::table_rows(MAP.instance, 2, MAP.transform), key].concat(),
                value: Some(stored(&value)),
            });
        }
    }
    if committed {
        rows.push(Write {
            key: keys::seed(version),
            value: Some(stored(&seed(version))),
        });
    }
    rows.push(Write {
        key: keys::version(),
        value: Some(stored(&version.encode())),
    });
    rows
}

/// The store, with the agent's version and applied index kept in step.
struct Agent {
    store: Fjall,
    version: AtomicU64,
}

impl Agent {
    /// Apply one result's rows through the writer, without a sync, as the
    /// node does.
    fn apply(&self, writer: &StorageThread, keys: &[u64], committed: bool) {
        let version = self.version.fetch_add(1, Ordering::SeqCst) + 1;
        self.apply_rows(writer, version, rows(version, keys, committed));
    }

    fn apply_rows(&self, writer: &StorageThread, version: u64, writes: Vec<Write>) {
        let apply = Change::Apply {
            agent: AGENT,
            epoch: 0,
            index: version,
            writes,
        };
        smol::block_on(writer.commit(vec![apply])).unwrap();
    }
}

/// Build to the end through `writer`: the keys and batches it built.
fn build(store: &Fjall, writer: &StorageThread) -> (u64, u64) {
    let Some(mut build) = Build::start(store, AGENT).unwrap() else {
        return (0, 0);
    };
    let mut batches = 0;
    while let Some(change) = build.next_batch().unwrap() {
        smol::block_on(writer.commit(vec![change])).unwrap();
        batches += 1;
    }
    (build.dirty_read(), batches)
}

fn main() {
    let args = support::args();
    let keys: u64 = args
        .first()
        .expect("tree-bench <keys> [rate] [seconds]")
        .parse()
        .unwrap();
    let rate: u64 = args.get(1).map_or(20_000, |rate| rate.parse().unwrap());
    let seconds: u64 = args.get(2).map_or(30, |seconds| seconds.parse().unwrap());
    let dir = support::data_dir("tree-bench");
    let agent = Arc::new(Agent {
        store: Fjall::open(&dir).unwrap(),
        version: AtomicU64::new(0),
    });
    let writer = Arc::new(StorageThread::spawn(agent.store.clone(), Arc::new(NoHooks)));

    // The map, loaded in results of 10,000 writes, then built from scratch.
    let started = Instant::now();
    let all: Vec<u64> = (0..keys).collect();
    for chunk in all.chunks(10_000) {
        agent.apply(&writer, chunk, true);
    }
    let load = started.elapsed();
    let started = Instant::now();
    let (built, batches) = build(&agent.store, &writer);
    let scratch = started.elapsed();
    println!(
        "{keys} keys: load {:.2} µs/write; build from scratch {:.2} µs/key ({built} keys, {batches} batches)",
        us(load, keys),
        us(scratch, built),
    );

    // The apply path: results of 1,000 random writes, committed or not, on
    // the store compacted, as after a long run, not behind the load's
    // compactions.
    agent.store.compact().unwrap();
    let mut rng = Random(0x2545_f491_4f6c_dd1d);
    let mut random = |count: u64| -> Vec<u64> { (0..count).map(|_| rng.draw() % keys).collect() };
    // The rows are made first: accumulate writes keys the work result names,
    // and hashes nothing. Results of each kind alternate, so the flushes and
    // compactions each leaves fall on both alike.
    let rounds = 200u64;
    let first = agent.version.load(Ordering::SeqCst) + 1;
    let results: Vec<(bool, Vec<Write>)> = (first..first + 2 * rounds)
        .map(|version| {
            let committed = version % 2 == first % 2;
            (committed, rows(version, &random(PER_RESULT), committed))
        })
        .collect();
    let mut took = [Duration::ZERO; 2];
    for (committed, writes) in results {
        let version = agent.version.fetch_add(1, Ordering::SeqCst) + 1;
        let started = Instant::now();
        agent.apply_rows(&writer, version, writes);
        took[usize::from(committed)] += started.elapsed();
    }
    let table = us(took[0], rounds * PER_RESULT);
    let committed = us(took[1], rounds * PER_RESULT);
    println!(
        "apply path: a table write {table:.2} µs, a committed write (value and dirty rows) {committed:.2} µs"
    );
    let (built, batches) = build(&agent.store, &writer);
    println!("caught up: {built} dirty rows in {batches} batches");

    // The builder keeping up: results at `rate` writes a second through the
    // writer, the builder building one after another meanwhile.
    let stop = Arc::new(AtomicBool::new(false));
    let applying = {
        let agent = Arc::clone(&agent);
        let writer = Arc::clone(&writer);
        let stop = Arc::clone(&stop);
        std::thread::spawn(move || {
            let mut rng = Random(0x9e37_79b9_7f4a_7c15);
            let every = Duration::from_secs_f64(PER_RESULT as f64 / rate as f64);
            let started = Instant::now();
            let mut results = 0u32;
            while !stop.load(Ordering::SeqCst) {
                let keys: Vec<u64> = (0..PER_RESULT).map(|_| rng.draw() % keys).collect();
                agent.apply(&writer, &keys, true);
                results += 1;
                if let Some(wait) =
                    (started + every * results).checked_duration_since(Instant::now())
                {
                    std::thread::sleep(wait);
                }
            }
            u64::from(results) * PER_RESULT
        })
    };
    let started = Instant::now();
    let mut builds = 0u64;
    let mut built = 0u64;
    let mut most_behind = 0u64;
    let mut build_times = Vec::new();
    while started.elapsed() < Duration::from_secs(seconds) {
        let at = agent.version.load(Ordering::SeqCst);
        let (_, version) = roots::root(&agent.store.snapshot(), AGENT, &MAP).unwrap();
        most_behind = most_behind.max(at.saturating_sub(version));
        let began = Instant::now();
        let (keys, _) = build(&agent.store, &writer);
        if keys == 0 {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }
        build_times.push(began.elapsed());
        builds += 1;
        built += keys;
    }
    stop.store(true, Ordering::SeqCst);
    let written = applying.join().unwrap();
    let elapsed = started.elapsed();
    let began = Instant::now();
    let (left, _) = build(&agent.store, &writer);
    let catch_up = began.elapsed();
    build_times.sort();
    let median = build_times
        .get(build_times.len() / 2)
        .copied()
        .unwrap_or_default();
    println!(
        "sustained {:.0} committed writes/s for {:.0} s: {builds} builds of {built} dirty rows ({:.0} rows/s built), \
         median build {:.1} ms, at most {most_behind} versions behind, {left} rows left after, caught up in {:.1} ms",
        written as f64 / elapsed.as_secs_f64(),
        elapsed.as_secs_f64(),
        built as f64 / elapsed.as_secs_f64(),
        median.as_secs_f64() * 1e3,
        catch_up.as_secs_f64() * 1e3,
    );
    drop(writer);
    drop(agent);
    std::fs::remove_dir_all(&dir).unwrap();
}
