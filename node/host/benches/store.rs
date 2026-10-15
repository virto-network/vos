//! Store costs: a table of 64-byte rows loaded, compacted, read (hits and
//! misses), updated and scanned through the node's `Store`, with the agent
//! key layout, at a given row count and tuning.
//!
//! `store-bench <rows> [variant...]`; variants are `default`, `filters`
//! (last-level filters kept), and on top of the default `hash` (in-block
//! hash index), `pin` (filters and indexes pinned) and `cache2g`. Data goes
//! under `target/`: on the reference laptop `/tmp` is tmpfs.
//!
//! The variant `writes` times point reads on the table alone, then while
//! 64 other agents write as the 64-agent run's do, at `WRITE_RATE` inputs
//! a second (40,000): over one whole cycle of the state partition's
//! memtable, from one rotation under the load to the next, past the first
//! minute's.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use vos_node::store::{Fjall, HardState, LogEntry, PersistMode, Tuning};
use vos_wire::defaults::REPLY_WINDOW;
use vos_wire::ids::{AgentId, InstanceId, SessionId};
use vos_wire::keys;
use vos_wire::result::Write;

const AGENT: AgentId = AgentId(7);
const VALUE: usize = 64;
const OPS: u64 = 1_000_000;
/// Reads per snapshot, as one refine's reads share one.
const READS_PER_SNAPSHOT: u64 = 1_000;

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// Row ids spread over u64, as account ids or hashed keys would be.
fn row(i: u64) -> Vec<u8> {
    [
        keys::table_prefix(InstanceId(0), 1),
        i.wrapping_mul(0x9e37_79b9_7f4a_7c15).to_be_bytes().to_vec(),
    ]
    .concat()
}

fn us(elapsed: Duration, ops: u64) -> f64 {
    elapsed.as_secs_f64() * 1e6 / ops as f64
}

fn tuning(variant: &str) -> Tuning {
    match variant {
        "default" | "writes" => Tuning::default(),
        "filters" => Tuning {
            expect_hits: false,
            ..Tuning::default()
        },
        "hash" => Tuning {
            hash_ratio: 0.75,
            ..Tuning::default()
        },
        "pin" => Tuning {
            pin_all: true,
            ..Tuning::default()
        },
        "cache2g" => Tuning {
            cache_bytes: 2 << 30,
            ..Tuning::default()
        },
        other => panic!("unknown variant {other}"),
    }
}

fn reads(store: &Fjall, rng: &mut XorShift, rows: u64, hit: bool) -> f64 {
    let started = Instant::now();
    let mut found = 0;
    for _ in 0..OPS / READS_PER_SNAPSHOT {
        let view = store.snapshot();
        for _ in 0..READS_PER_SNAPSHOT {
            let key = if hit {
                row(rng.next() % rows)
            } else {
                row(rows + rng.next() % rows)
            };
            found += u64::from(view.get(AGENT, &key).unwrap().is_some());
        }
    }
    let elapsed = started.elapsed();
    assert_eq!(found, if hit { OPS } else { 0 });
    us(elapsed, OPS)
}

/// Point-read latencies in 10 ns buckets up to 100 µs, and their sum.
struct Histogram {
    buckets: Vec<u64>,
    over: u64,
    count: u64,
    total: Duration,
}

impl Histogram {
    const BUCKET_NS: u64 = 10;

    fn new() -> Self {
        Self {
            buckets: vec![0; 10_000],
            over: 0,
            count: 0,
            total: Duration::ZERO,
        }
    }

    fn record(&mut self, took: Duration) {
        let at = (took.as_nanos() as u64 / Self::BUCKET_NS) as usize;
        match self.buckets.get_mut(at) {
            Some(bucket) => *bucket += 1,
            None => self.over += 1,
        }
        self.count += 1;
        self.total += took;
    }

    fn mean_us(&self) -> f64 {
        self.total.as_secs_f64() * 1e6 / self.count.max(1) as f64
    }

    /// The bucket's upper bound at `quantile`, in µs: past the last, the
    /// last's.
    fn at_us(&self, quantile: f64) -> f64 {
        let wanted = (self.count as f64 * quantile).ceil() as u64;
        let mut seen = 0;
        for (at, &bucket) in self.buckets.iter().enumerate() {
            seen += bucket;
            if seen >= wanted {
                return ((at as u64 + 1) * Self::BUCKET_NS) as f64 / 1e3;
            }
        }
        (self.buckets.len() as u64 * Self::BUCKET_NS) as f64 / 1e3
    }
}

/// `count` timed hits on the table, a snapshot every
/// `READS_PER_SNAPSHOT`.
fn timed_reads(store: &Fjall, rng: &mut XorShift, rows: u64, count: u64, into: &mut Histogram) {
    for _ in 0..count / READS_PER_SNAPSHOT {
        let view = store.snapshot();
        for _ in 0..READS_PER_SNAPSHOT {
            let key = row(rng.next() % rows);
            let started = Instant::now();
            let found = view.get(AGENT, &key).unwrap();
            into.record(started.elapsed());
            assert!(found.is_some());
        }
    }
}

/// Bytes from `rng`, which no block compression shrinks.
fn random_bytes(rng: &mut XorShift, len: usize) -> Vec<u8> {
    (0..len.div_ceil(8))
        .flat_map(|_| rng.next().to_le_bytes())
        .take(len)
        .collect()
}

/// The agents writing beside the table, and how they write, as the
/// in-process 64-agent run writes at 16 sessions each: inputs a batch,
/// batches a flush (2.6 on average: 13 over every 5 flushes), sessions an
/// agent, and a work result's log entry, about 1,000 bytes for its 10
/// inputs.
const WRITERS: u32 = 64;
const INPUTS: u64 = 10;
const FLUSH_BATCHES: [u64; 5] = [3, 3, 3, 2, 2];
const SESSIONS: u64 = 16;
const ENTRY_BYTES: usize = 1_000;
/// The node's compaction: every so many entries, keeping a tail.
const COMPACT_EVERY: u64 = 1_024;
const COMPACT_TAIL: u64 = 256;

/// The 64 agents' writes at `rate` inputs a second until `stop`: per flush,
/// their log entries in one synced commit and their applies in one
/// buffered, as the node's writer does. Each input applies its session's
/// mark, a kept reply and the reply it pushes out of the window; each
/// batch its agent's state, batch time, last result and hard state.
/// Counts the inputs written.
fn write_load(store: &Fjall, rate: u64, stop: &AtomicBool, written: &AtomicU64) {
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    let mut indexes = vec![0u64; WRITERS as usize];
    let mut sequences = vec![0u64; (u64::from(WRITERS) * SESSIONS) as usize];
    let mut turn = 0u32;
    let mut next = Instant::now();
    for &batches in FLUSH_BATCHES.iter().cycle() {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        if let Some(wait) = next.checked_duration_since(Instant::now()) {
            std::thread::sleep(wait);
        }
        next += Duration::from_secs_f64((batches * INPUTS) as f64 / rate as f64);
        let mut appends = store.batch();
        let mut applies = store.batch();
        for _ in 0..batches {
            let at = turn % WRITERS;
            turn = turn.wrapping_add(1);
            let agent = AgentId(100 + at);
            indexes[at as usize] += 1;
            let index = indexes[at as usize];
            appends.append(
                agent,
                index,
                &LogEntry::result(1, random_bytes(&mut rng, ENTRY_BYTES)),
            );
            let mut writes = Vec::with_capacity(3 * INPUTS as usize + 2);
            for input in 0..INPUTS {
                let session = (index * INPUTS + input) % SESSIONS;
                let sequence = &mut sequences[(u64::from(at) * SESSIONS + session) as usize];
                *sequence += 1;
                let id = SessionId(session);
                writes.push(Write {
                    key: keys::session(id),
                    value: Some(sequence.to_be_bytes().to_vec()),
                });
                writes.push(Write {
                    key: keys::reply(id, *sequence),
                    value: Some(random_bytes(&mut rng, 16)),
                });
                if *sequence > REPLY_WINDOW {
                    writes.push(Write {
                        key: keys::reply(id, *sequence - REPLY_WINDOW),
                        value: None,
                    });
                }
            }
            writes.push(Write {
                key: keys::instance_struct(InstanceId(1)),
                value: Some(index.to_be_bytes().to_vec()),
            });
            writes.push(Write {
                key: keys::batch_time(),
                value: Some(index.to_be_bytes().to_vec()),
            });
            applies.apply(agent, 0, index, &writes);
            applies.last_result(agent, index, &[0x77; 32]);
            applies.hard_state(
                agent,
                &HardState {
                    term: 1,
                    vote: None,
                    commit: index,
                },
            );
            if index.is_multiple_of(COMPACT_EVERY) {
                applies.compact(agent, index - COMPACT_TAIL, 1, None);
            }
        }
        appends.commit(PersistMode::SyncAll).unwrap();
        applies.commit(PersistMode::Buffer).unwrap();
        written.fetch_add(batches * INPUTS, Ordering::Relaxed);
    }
}

/// Wait until the state partition's active memtable rotates, at or after
/// `after`: its size falls as another takes its place.
fn rotated(store: &Fjall, after: Instant, limit: Duration) {
    let until = Instant::now() + limit;
    let mut last = store.state_memtable_bytes();
    loop {
        std::thread::sleep(Duration::from_millis(50));
        let now = store.state_memtable_bytes();
        if now < last && Instant::now() >= after {
            return;
        }
        last = now;
        assert!(Instant::now() < until, "no rotation of the state memtable");
    }
}

/// Point reads on the table alone, then under the 64 agents' writes over
/// one whole cycle of the state partition's memtable, from one rotation
/// to the next: every read searches the active memtable first, then any
/// sealed one not yet flushed. The first minute's rotations are passed
/// over: the table's load left rows in the memtable, and the other
/// partitions' cycles have only begun.
fn under_writes(store: &Fjall, rng: &mut XorShift, rows: u64) {
    let rate: u64 = std::env::var("WRITE_RATE").map_or(40_000, |rate| rate.parse().unwrap());
    // About two cycles' time at 40k/s, longer in proportion below it.
    let limit = Duration::from_secs(1_200 * 40_000 / rate.clamp(1, 40_000));
    let mut alone = Histogram::new();
    timed_reads(store, rng, rows, OPS, &mut alone);
    println!(
        "{rows} rows, reads alone: mean {:.2} µs, p50 {:.2} µs, p99 {:.2} µs ({} past 100 µs)",
        alone.mean_us(),
        alone.at_us(0.5),
        alone.at_us(0.99),
        alone.over
    );
    let stop = AtomicBool::new(false);
    let written = AtomicU64::new(0);
    std::thread::scope(|scope| {
        scope.spawn(|| write_load(store, rate, &stop, &written));
        let started = Instant::now();
        rotated(store, started + Duration::from_secs(60), limit);
        let settled = started.elapsed();
        // Reads in windows until the next rotation, each window's mean
        // beside the active memtable's size and the sealed ones' count when
        // it began.
        let before = written.load(Ordering::Relaxed);
        let cycle = Instant::now();
        let mut under = Histogram::new();
        let mut windows: Vec<(u64, usize, f64)> = Vec::new();
        let mut last = store.state_memtable_bytes();
        loop {
            let sealed = store.state_sealed_memtables();
            let mut window = Histogram::new();
            timed_reads(store, rng, rows, 100_000, &mut window);
            windows.push((last, sealed, window.mean_us()));
            under
                .buckets
                .iter_mut()
                .zip(&window.buckets)
                .for_each(|(sum, add)| *sum += add);
            under.over += window.over;
            under.count += window.count;
            under.total += window.total;
            let now = store.state_memtable_bytes();
            if now < last {
                break;
            }
            last = now;
            assert!(cycle.elapsed() < limit, "no second rotation");
        }
        let took = cycle.elapsed();
        let kept = (written.load(Ordering::Relaxed) - before) as f64 / took.as_secs_f64();
        stop.store(true, Ordering::Relaxed);
        let mib = |bytes: u64| bytes as f64 / f64::from(1 << 20);
        println!(
            "{rows} rows, reads under {rate}/s inputs written ({kept:.0}/s kept), over one \
             memtable cycle of {:.0} s from a rotation at {:.0} s, ending at {:.1} MiB: \
             mean {:.2} µs, p50 {:.2} µs, p99 {:.2} µs ({} past 100 µs); {:.0} MiB on disk",
            took.as_secs_f64(),
            settled.as_secs_f64(),
            mib(last),
            under.mean_us(),
            under.at_us(0.5),
            under.at_us(0.99),
            under.over,
            mib(store.disk_space().unwrap()),
        );
        let quarter = |at: usize| windows[(windows.len() - 1) * at / 4];
        let marks: Vec<String> = (0..=4)
            .map(|at| {
                let (bytes, sealed, mean) = quarter(at);
                format!("{:.1} MiB + {sealed} sealed: {mean:.2} µs", mib(bytes))
            })
            .collect();
        println!("  through the cycle: {}", marks.join(", "));
    });
}

fn run(rows: u64, variant: &str) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../target")
        .join(format!("store-bench-{}", std::process::id()));
    let store = Fjall::open_tuned(&dir, tuning(variant)).unwrap();
    let value = vec![0xa5u8; VALUE];

    let started = Instant::now();
    let chunk = 100_000;
    let mut index = 0;
    for start in (0..rows).step_by(chunk) {
        let writes: Vec<_> = (start..(start + chunk as u64).min(rows))
            .map(|i| Write {
                key: row(i),
                value: Some(value.clone()),
            })
            .collect();
        index += 1;
        let mut batch = store.batch();
        batch.apply(AGENT, 0, index, &writes);
        batch.commit(PersistMode::Buffer).unwrap();
    }
    let load = started.elapsed();
    let started = Instant::now();
    store.compact().unwrap();
    let compact = started.elapsed();

    let mut rng = XorShift(0x2545_f491_4f6c_dd1d);
    // Warm the cache with one pass of hits before measuring.
    reads(&store, &mut rng, rows, true);
    if variant == "writes" {
        under_writes(&store, &mut rng, rows);
        drop(store);
        std::fs::remove_dir_all(&dir).unwrap();
        return;
    }
    let hit = reads(&store, &mut rng, rows, true);
    let miss = reads(&store, &mut rng, rows, false);

    let mut update = |size: u64, durability: PersistMode, rounds: u64| {
        let started = Instant::now();
        for _ in 0..rounds {
            let writes: Vec<_> = (0..size)
                .map(|_| Write {
                    key: row(rng.next() % rows),
                    value: Some(value.clone()),
                })
                .collect();
            index += 1;
            let mut batch = store.batch();
            batch.apply(AGENT, 0, index, &writes);
            batch.commit(durability).unwrap();
        }
        us(started.elapsed(), size * rounds)
    };
    let update_1 = update(1, PersistMode::Buffer, 20_000);
    let update_1000 = update(1_000, PersistMode::Buffer, 500);
    let update_1000_synced = update(1_000, PersistMode::SyncAll, 100);
    let hit_after = reads(&store, &mut rng, rows, true);

    let started = Instant::now();
    let mut scanned = 0u64;
    let table = keys::table_prefix(InstanceId(0), 1);
    for _ in 0..1_000 {
        let view = store.snapshot();
        let from = row(rng.next() % rows);
        for entry in view.scan(AGENT, &table, Some(&from)).take(1_000) {
            entry.unwrap();
            scanned += 1;
        }
    }
    let scan = us(started.elapsed(), scanned);

    println!(
        "{rows} rows, {variant}: load {:.2} µs/row, compact {:.1} s, {:.0} MiB; \
         read hit {hit:.2} µs (after updates {hit_after:.2}), miss {miss:.2} µs; \
         update 1-row {update_1:.2} µs, 1000-row {update_1000:.2} µs, \
         1000-row synced {update_1000_synced:.2} µs; scan {scan:.3} µs/row",
        us(load, rows),
        compact.as_secs_f64(),
        store.disk_space().unwrap() as f64 / f64::from(1 << 20),
    );
    drop(store);
    std::fs::remove_dir_all(&dir).unwrap();
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let rows: u64 = args
        .get(1)
        .expect("store-bench <rows> [variant...]")
        .parse()
        .unwrap();
    let variants: Vec<&str> = if args.len() > 2 {
        args[2..].iter().map(String::as_str).collect()
    } else {
        vec!["default", "filters"]
    };
    for variant in variants {
        run(rows, variant);
    }
}
