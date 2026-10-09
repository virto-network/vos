//! Store costs (slice 2, step 2.2): S4's table workload through the node's
//! `Store`, with the agent key layout, at a given row count and tuning.
//!
//! `store-bench <rows> [variant...]`; variants are `default`, `filters`
//! (last-level filters kept), and on top of the default `hash` (in-block
//! hash index), `pin` (filters and indexes pinned) and `cache2g`. Data goes
//! under `target/`: on the reference laptop `/tmp` is tmpfs.

use std::time::{Duration, Instant};

use vos_node::store::{Batch, Durability, Fjall, Store, Tuning, View};
use vos_wire::ids::{AgentId, InstanceId};
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
        "default" => Tuning::default(),
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
        batch.apply(AGENT, index, &writes);
        batch.commit(Durability::Buffered).unwrap();
    }
    let load = started.elapsed();
    let started = Instant::now();
    store.compact().unwrap();
    let compact = started.elapsed();

    let mut rng = XorShift(0x2545_f491_4f6c_dd1d);
    // Warm the cache with one pass of hits before measuring.
    reads(&store, &mut rng, rows, true);
    let hit = reads(&store, &mut rng, rows, true);
    let miss = reads(&store, &mut rng, rows, false);

    let mut update = |size: u64, durability: Durability, rounds: u64| {
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
            batch.apply(AGENT, index, &writes);
            batch.commit(durability).unwrap();
        }
        us(started.elapsed(), size * rounds)
    };
    let update_1 = update(1, Durability::Buffered, 20_000);
    let update_1000 = update(1_000, Durability::Buffered, 500);
    let update_1000_synced = update(1_000, Durability::Synced, 100);
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
