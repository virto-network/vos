//! Large tables and committed roots.
//!
//! `table <rows>`: redb point reads and writes, inserts and scans at a given
//! table size.
//! `tree <keys> <key bits>`: root maintenance cost on a binary radix tree
//! that stores only branching nodes, under two hash formats:
//! - fixed-depth: today's `CommittedMap` math. Every key bit is a tree
//!   level, so a child is lifted through empty-sibling spines up to its
//!   parent, and both children are lifted whenever a parent is rehashed;
//! - compressed: a leaf hash commits its full key, a branch hash commits
//!   its split level and both children. One hash per stored node.
//! `hash <guest.elf>`: BLAKE2b in the PVM versus native.

use std::time::{Duration, Instant};

use redb::{Database, Durability, TableDefinition};

const ROWS: TableDefinition<u64, &[u8]> = TableDefinition::new("rows");
const VALUE: usize = 64;

fn data_dir() -> std::path::PathBuf {
    // On the real disk; /tmp is tmpfs.
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("target")
        .join(format!("data-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

/// Keys are a random permutation-like spread over u64 so inserts land all
/// over the tree, as account ids or hashed keys would.
fn key(i: u64) -> u64 {
    i.wrapping_mul(0x9e37_79b9_7f4a_7c15)
}

// ── Tables ──────────────────────────────────────────────────

fn durability(commit: u64, durable_every: u64) -> Durability {
    if durable_every > 0 && commit % durable_every == 0 { Durability::Immediate } else { Durability::None }
}

fn table(rows: u64, durable_every: u64) {
    let mut commits = 0u64;
    let dir = data_dir();
    let path = dir.join("table.redb");
    let db = Database::create(&path).unwrap();
    let value = [0xa5u8; VALUE];

    let started = Instant::now();
    let chunk = 200_000;
    let mut i = 0;
    while i < rows {
        let mut txn = db.begin_write().unwrap();
        commits += 1;
        txn.set_durability(durability(commits, durable_every.min(1)));
        {
            let mut t = txn.open_table(ROWS).unwrap();
            for j in i..(i + chunk).min(rows) {
                t.insert(key(j), value.as_slice()).unwrap();
            }
        }
        txn.commit().unwrap();
        i += chunk;
    }
    let mut txn = db.begin_write().unwrap();
    txn.set_durability(Durability::Immediate);
    txn.commit().unwrap();
    let load = started.elapsed();
    let size = std::fs::metadata(&path).unwrap().len();
    println!(
        "redb, durable commit every {durable_every} (0 = never): \
         {rows} rows of {VALUE} B: loaded in {:.1} s ({:.2} µs per row), file {:.0} MiB",
        load.as_secs_f64(),
        us(load) / rows as f64,
        size as f64 / (1 << 20) as f64,
    );

    let mut rng = XorShift(0x2545_f491_4f6c_dd1d);
    let ops = 1_000_000;

    // Point reads in one read transaction (a refine reads its batch in one).
    let txn = db.begin_read().unwrap();
    let t = txn.open_table(ROWS).unwrap();
    let started = Instant::now();
    let mut found = 0;
    for _ in 0..ops {
        if t.get(key(rng.next() % rows)).unwrap().is_some() {
            found += 1;
        }
    }
    let read = started.elapsed();
    assert_eq!(found, ops);
    let started = Instant::now();
    for _ in 0..ops {
        let _ = t.get(rng.next() | 1).unwrap();
    }
    let miss = started.elapsed();
    drop(t);
    drop(txn);

    // A read transaction per lookup (a query outside any batch).
    let started = Instant::now();
    for _ in 0..100_000 {
        let txn = db.begin_read().unwrap();
        let t = txn.open_table(ROWS).unwrap();
        let _ = t.get(key(rng.next() % rows)).unwrap();
    }
    let read_txn = started.elapsed() / 100_000;

    // Updates of existing rows, one transaction per batch (one accumulate
    // per log entry), without fsync as section 9.5 proposes.
    let mut update = |batch: u64, fsync: bool, rounds: u64| {
        let started = Instant::now();
        for _ in 0..rounds {
            let mut txn = db.begin_write().unwrap();
            commits += 1;
            txn.set_durability(if fsync { Durability::Immediate } else { durability(commits, durable_every) });
            {
                let mut t = txn.open_table(ROWS).unwrap();
                for _ in 0..batch {
                    t.insert(key(rng.next() % rows), value.as_slice()).unwrap();
                }
            }
            txn.commit().unwrap();
        }
        us(started.elapsed()) / (batch * rounds) as f64
    };
    let update_1 = update(1, false, 20_000);
    let update_100 = update(100, false, 2_000);
    let update_1000 = update(1000, false, 500);
    let update_1000_fsync = update(1000, true, 100);

    // Inserts of new keys.
    let started = Instant::now();
    let mut next = rows;
    for _ in 0..500 {
        let mut txn = db.begin_write().unwrap();
        commits += 1;
        txn.set_durability(durability(commits, durable_every));
        {
            let mut t = txn.open_table(ROWS).unwrap();
            for _ in 0..1000 {
                t.insert(key(next), value.as_slice()).unwrap();
                next += 1;
            }
        }
        txn.commit().unwrap();
    }
    let insert = us(started.elapsed()) / 500_000.0;

    // Ordered scans of 1,000 rows from random starting points.
    let txn = db.begin_read().unwrap();
    let t = txn.open_table(ROWS).unwrap();
    let started = Instant::now();
    let mut scanned = 0;
    for _ in 0..1000 {
        for row in t.range(rng.next()..).unwrap().take(1000) {
            row.unwrap();
            scanned += 1;
        }
    }
    let scan = us(started.elapsed()) / scanned as f64;

    println!(
        "  read hit {:.2} µs, miss {:.2} µs, with own read transaction {:.2} µs",
        us(read) / ops as f64,
        us(miss) / ops as f64,
        us(read_txn),
    );
    println!(
        "  update (no fsync) per row: batch 1 {update_1:.2} µs, batch 100 {update_100:.2} µs, \
         batch 1000 {update_1000:.2} µs; batch 1000 with fsync {update_1000_fsync:.2} µs"
    );
    println!("  insert new key (batch 1000) {insert:.2} µs; scan {scan:.3} µs per row");
    drop(t);
    drop(txn);
    drop(db);
    println!(
        "  file after the runs: {:.0} MiB",
        std::fs::metadata(&path).unwrap().len() as f64 / (1 << 20) as f64
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn dir_size(path: &std::path::Path) -> u64 {
    std::fs::read_dir(path)
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let meta = entry.metadata().unwrap();
            if meta.is_dir() { dir_size(&entry.path()) } else { meta.len() }
        })
        .sum()
}

/// The same operations on fjall, an LSM tree. Updates go to the memtable
/// and a journal; compaction runs on background threads.
fn table_lsm(rows: u64) {
    use fjall::{Database, KeyspaceCreateOptions, PersistMode};
    let dir = data_dir();
    // A 1 GiB block cache, as redb's default.
    let db = Database::builder(dir.join("lsm")).cache_size(1 << 30).open().unwrap();
    let t = db.keyspace("rows", KeyspaceCreateOptions::default).unwrap();
    let value = [0xa5u8; VALUE];

    let started = Instant::now();
    let chunk = 200_000;
    let mut i = 0;
    while i < rows {
        let mut batch = db.batch();
        for j in i..(i + chunk).min(rows) {
            batch.insert(&t, key(j).to_be_bytes(), value);
        }
        batch.commit().unwrap();
        i += chunk;
    }
    db.persist(PersistMode::SyncAll).unwrap();
    let load = started.elapsed();
    // Settle the bulk load into one sorted run before reading.
    let started = Instant::now();
    t.major_compact().unwrap();
    let compact = started.elapsed();
    println!(
        "fjall: {rows} rows of {VALUE} B: loaded in {:.1} s ({:.2} µs per row), compacted in {:.1} s, files {:.0} MiB",
        load.as_secs_f64(),
        us(load) / rows as f64,
        compact.as_secs_f64(),
        dir_size(&dir) as f64 / (1 << 20) as f64,
    );

    let mut rng = XorShift(0x2545_f491_4f6c_dd1d);
    let ops = 1_000_000;
    let started = Instant::now();
    let mut found = 0;
    for _ in 0..ops {
        if t.get(key(rng.next() % rows).to_be_bytes()).unwrap().is_some() {
            found += 1;
        }
    }
    let read = started.elapsed();
    assert_eq!(found, ops);
    let started = Instant::now();
    for _ in 0..ops {
        let _ = t.get((rng.next() | 1).to_be_bytes()).unwrap();
    }
    let miss = started.elapsed();

    let mut update = |batch: u64, fsync: bool, rounds: u64| {
        let started = Instant::now();
        for _ in 0..rounds {
            let mut b = db.batch().durability(fsync.then_some(PersistMode::SyncAll));
            for _ in 0..batch {
                b.insert(&t, key(rng.next() % rows).to_be_bytes(), value);
            }
            b.commit().unwrap();
        }
        us(started.elapsed()) / (batch * rounds) as f64
    };
    let update_1 = update(1, false, 20_000);
    let update_100 = update(100, false, 2_000);
    let update_1000 = update(1000, false, 500);
    let update_1000_fsync = update(1000, true, 100);

    let started = Instant::now();
    for _ in 0..ops {
        let _ = t.get(key(rng.next() % rows).to_be_bytes()).unwrap();
    }
    let read_after = started.elapsed();

    let started = Instant::now();
    let mut next = rows;
    for _ in 0..500 {
        let mut b = db.batch();
        for _ in 0..1000 {
            b.insert(&t, key(next).to_be_bytes(), value);
            next += 1;
        }
        b.commit().unwrap();
    }
    let insert = us(started.elapsed()) / 500_000.0;

    let started = Instant::now();
    let mut scanned = 0;
    for _ in 0..1000 {
        for row in t.range(rng.next().to_be_bytes()..).take(1000) {
            row.into_inner().unwrap();
            scanned += 1;
        }
    }
    let scan = us(started.elapsed()) / scanned as f64;

    println!(
        "  read hit {:.2} µs, miss {:.2} µs; hit after the update runs {:.2} µs",
        us(read) / ops as f64,
        us(miss) / ops as f64,
        us(read_after) / ops as f64
    );
    println!(
        "  update (no fsync) per row: batch 1 {update_1:.2} µs, batch 100 {update_100:.2} µs, \
         batch 1000 {update_1000:.2} µs; batch 1000 with fsync {update_1000_fsync:.2} µs"
    );
    println!("  insert new key (batch 1000) {insert:.2} µs; scan {scan:.3} µs per row");
    db.persist(PersistMode::SyncAll).unwrap();
    println!("  files after the runs: {:.0} MiB", dir_size(&dir) as f64 / (1 << 20) as f64);
    drop(t);
    drop(db);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Durable log appends, as S3's node log writer issues them: `entries`
/// entries of 1 KiB keyed by (agent, index) per commit, fsynced.
fn log_appends(entries: u64) {
    use fjall::{Database as Lsm, KeyspaceCreateOptions, PersistMode};
    let dir = data_dir();
    let payload = [0xa5u8; 1024];
    let window = Duration::from_secs(3);

    let db = Database::create(dir.join("log.redb")).unwrap();
    const LOG: TableDefinition<(u32, u64), &[u8]> = TableDefinition::new("log");
    let started = Instant::now();
    let (mut commits, mut index) = (0u64, 0u64);
    while started.elapsed() < window {
        let mut txn = db.begin_write().unwrap();
        txn.set_durability(Durability::Immediate);
        {
            let mut t = txn.open_table(LOG).unwrap();
            for _ in 0..entries {
                t.insert(((index % 16) as u32, index), payload.as_slice()).unwrap();
                index += 1;
            }
        }
        txn.commit().unwrap();
        commits += 1;
    }
    let redb = us(started.elapsed()) / commits as f64;

    let lsm = Lsm::builder(dir.join("log.lsm")).open().unwrap();
    let t = lsm.keyspace("log", KeyspaceCreateOptions::default).unwrap();
    let started = Instant::now();
    let (mut commits, mut index) = (0u64, 0u64);
    while started.elapsed() < window {
        let mut b = lsm.batch().durability(Some(PersistMode::SyncData));
        for _ in 0..entries {
            let mut key = [0u8; 12];
            key[..4].copy_from_slice(&((index % 16) as u32).to_be_bytes());
            key[4..].copy_from_slice(&index.to_be_bytes());
            b.insert(&t, key, payload);
            index += 1;
        }
        b.commit().unwrap();
        commits += 1;
    }
    let fjall = us(started.elapsed()) / commits as f64;
    println!(
        "durable append of {entries} × 1 KiB: redb {redb:.0} µs per commit ({:.0} entries/s), \
         fjall {fjall:.0} µs ({:.0} entries/s)",
        entries as f64 / redb * 1e6,
        entries as f64 / fjall * 1e6,
    );
    drop(t);
    drop(lsm);
    drop(db);
    let _ = std::fs::remove_dir_all(&dir);
}

// ── Committed roots ─────────────────────────────────────────

const NONE: u32 = u32::MAX;
const LEAF_DOMAIN: &[u8] = b"vos/smt/leaf";
const NODE_DOMAIN: &[u8] = b"vos/smt/node";

#[derive(Clone, Copy)]
enum Node {
    /// Key left-aligned in a u128.
    Leaf { key: u128, value: [u8; 32] },
    /// Splits on bit `level`; `prefix` holds the key bits above it.
    Branch { level: u16, prefix: u128, left: u32, right: u32 },
}

#[derive(Clone, Copy, PartialEq)]
enum Format {
    FixedDepth,
    Compressed,
}

struct Tree {
    bits: u32,
    nodes: Vec<Node>,
    hashes: Vec<[u8; 32]>,
    dirty: Vec<bool>,
    root: u32,
    format: Format,
    /// chain[d]: an empty subtree of height d (fixed-depth format).
    chain: Vec<[u8; 32]>,
    hashed: u64,
    /// Branch nodes rehashed: the node rows a row-backed tree rewrites.
    rewritten: u64,
}

fn bit(key: u128, level: u32) -> bool {
    (key >> (127 - level)) & 1 == 1
}

fn top_bits(level: u32) -> u128 {
    if level == 0 { 0 } else { !0u128 << (128 - level) }
}

impl Tree {
    fn new(bits: u32, format: Format) -> Self {
        let mut chain = vec![[0u8; 32]];
        for d in 1..=bits as usize {
            let previous = chain[d - 1];
            chain.push(hash(NODE_DOMAIN, &[&previous, &previous]));
        }
        Self {
            bits,
            nodes: Vec::new(),
            hashes: Vec::new(),
            dirty: Vec::new(),
            root: NONE,
            format,
            chain,
            hashed: 0,
            rewritten: 0,
        }
    }

    fn push(&mut self, node: Node) -> u32 {
        self.nodes.push(node);
        self.hashes.push([0; 32]);
        self.dirty.push(true);
        (self.nodes.len() - 1) as u32
    }

    fn level_of(&self, at: u32) -> u32 {
        match self.nodes[at as usize] {
            Node::Leaf { .. } => self.bits,
            Node::Branch { level, .. } => u32::from(level),
        }
    }

    fn key_of(&self, at: u32) -> u128 {
        match self.nodes[at as usize] {
            Node::Leaf { key, .. } => key,
            Node::Branch { prefix, .. } => prefix,
        }
    }

    fn branch(&mut self, level: u32, a: u32, b: u32, key: u128) -> u32 {
        let (left, right) = if bit(self.key_of(a), level) { (b, a) } else { (a, b) };
        self.push(Node::Branch {
            level: level as u16,
            prefix: key & top_bits(level),
            left,
            right,
        })
    }

    fn insert(&mut self, key: u128, value: [u8; 32]) {
        self.root = if self.root == NONE {
            self.push(Node::Leaf { key, value })
        } else {
            self.insert_at(self.root, key, value)
        };
    }

    fn insert_at(&mut self, at: u32, key: u128, value: [u8; 32]) -> u32 {
        match self.nodes[at as usize] {
            Node::Leaf { key: existing, .. } if existing == key => {
                self.nodes[at as usize] = Node::Leaf { key, value };
                self.dirty[at as usize] = true;
                at
            }
            Node::Leaf { key: existing, .. } => {
                let level = (existing ^ key).leading_zeros();
                let leaf = self.push(Node::Leaf { key, value });
                self.branch(level, at, leaf, key)
            }
            Node::Branch {
                level,
                prefix,
                left,
                right,
            } => {
                let level = u32::from(level);
                let differ = (key ^ prefix) & top_bits(level);
                if differ != 0 {
                    let split = differ.leading_zeros();
                    let leaf = self.push(Node::Leaf { key, value });
                    return self.branch(split, at, leaf, key);
                }
                if bit(key, level) {
                    let child = self.insert_at(right, key, value);
                    self.nodes[at as usize] = Node::Branch { level: level as u16, prefix, left, right: child };
                } else {
                    let child = self.insert_at(left, key, value);
                    self.nodes[at as usize] = Node::Branch { level: level as u16, prefix, left: child, right };
                }
                self.dirty[at as usize] = true;
                at
            }
        }
    }

    fn h(&mut self, domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
        self.hashed += 1;
        hash(domain, parts)
    }

    /// Fixed-depth: the hash of `child`'s subtree lifted to `level`
    /// through empty siblings, one hash per level.
    fn lift(&mut self, child: u32, level: u32) -> [u8; 32] {
        let mut h = self.hashes[child as usize];
        let key = self.key_of(child);
        let from = self.bits - self.level_of(child);
        let to = self.bits - level;
        for depth in from..to {
            let sibling = self.chain[depth as usize];
            h = if bit(key, self.bits - 1 - depth) {
                self.h(NODE_DOMAIN, &[&sibling, &h])
            } else {
                self.h(NODE_DOMAIN, &[&h, &sibling])
            };
        }
        h
    }

    fn rehash(&mut self, at: u32) -> [u8; 32] {
        if !self.dirty[at as usize] {
            return self.hashes[at as usize];
        }
        let hash = match self.nodes[at as usize] {
            Node::Leaf { key, value } => match self.format {
                Format::FixedDepth => self.h(LEAF_DOMAIN, &[&value]),
                Format::Compressed => self.h(LEAF_DOMAIN, &[&key.to_be_bytes(), &value]),
            },
            Node::Branch { level, left, right, .. } => {
                self.rewritten += 1;
                self.rehash(left);
                self.rehash(right);
                match self.format {
                    Format::FixedDepth => {
                        let l = self.lift(left, u32::from(level) + 1);
                        let r = self.lift(right, u32::from(level) + 1);
                        self.h(NODE_DOMAIN, &[&l, &r])
                    }
                    Format::Compressed => {
                        let (l, r) = (self.hashes[left as usize], self.hashes[right as usize]);
                        self.h(NODE_DOMAIN, &[&level.to_be_bytes(), &l, &r])
                    }
                }
            }
        };
        self.hashes[at as usize] = hash;
        self.dirty[at as usize] = false;
        hash
    }

    fn root_hash(&mut self) -> [u8; 32] {
        let top = self.rehash(self.root);
        match self.format {
            Format::FixedDepth => self.lift(self.root, 0),
            Format::Compressed => top,
        }
    }
}

fn hash(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut state = blake2b_simd::Params::new().hash_length(32).to_state();
    state.update(domain);
    for part in parts {
        state.update(part);
    }
    state.finalize().as_bytes().try_into().unwrap()
}

fn tree(keys: u64, bits: u32) {
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    let align = |k: u64| -> u128 {
        let k = u128::from(k) | (u128::from(rng_mix(k)) << 64);
        k << (128 - bits) >> (128 - bits) << (128 - bits)
    };
    let started = Instant::now();
    let mut tree = Tree::new(bits, Format::Compressed);
    for i in 0..keys {
        tree.insert(align(key(i)), [1; 32]);
    }
    let build = started.elapsed();
    let started = Instant::now();
    tree.root_hash();
    let full = started.elapsed();
    println!(
        "{keys} keys of {bits} bits: built in {:.1} s, {} nodes; full compressed root {:.1} s ({} hashes)",
        build.as_secs_f64(),
        tree.nodes.len(),
        full.as_secs_f64(),
        tree.hashed
    );
    // Both formats are timed on the same structure. Fixed-depth sibling
    // hashes are the compressed ones (placeholders), which leaves the
    // hashing work per update exact.
    for format in [Format::FixedDepth, Format::Compressed] {
        tree.format = format;
        let name = if format == Format::FixedDepth { "fixed-depth" } else { "compressed" };
        for batch in [1u64, 100, 1000, 10_000] {
            let rounds = (20_000 / batch).max(3);
            let mut elapsed = Duration::ZERO;
            let mut hashes = 0;
            let mut rows = 0;
            for _ in 0..rounds {
                let updates: Vec<u128> = (0..batch).map(|_| align(key(rng.next() % keys))).collect();
                let (before, rewritten) = (tree.hashed, tree.rewritten);
                let started = Instant::now();
                for k in &updates {
                    tree.insert(*k, [2; 32]);
                }
                tree.root_hash();
                elapsed += started.elapsed();
                hashes += tree.hashed - before;
                rows += tree.rewritten - rewritten;
            }
            let per = (batch * rounds) as f64;
            println!(
                "  {name:>11}, batch {batch:>5}: {:>6.1} hashes and {:>5.1} node rows per update, {:>7.2} µs per update",
                hashes as f64 / per,
                rows as f64 / per,
                us(elapsed) / per,
            );
        }
    }
}

fn rng_mix(k: u64) -> u64 {
    (k ^ (k >> 31)).wrapping_mul(0xbf58_476d_1ce4_e5b9)
}

// ── Hashing in the PVM ──────────────────────────────────────

fn pvm_hash(elf: &str) {
    use vos_pvm::refine::{Machine, MemoryModel, PreparedProgram};
    use vos_pvm::{ExitReason, PvmBackend};
    let spi = vos_pvm_compiler::link_elf_spi(&std::fs::read(elf).unwrap()).expect("link");
    let n: u64 = 20_000;
    let native = {
        let mut left = [7u8; 32];
        let started = Instant::now();
        for _ in 0..n {
            left = hash(NODE_DOMAIN, &[&left, &[9u8; 32]]);
        }
        (us(started.elapsed()) / n as f64, left)
    };
    println!("native BLAKE2b, 76-byte input: {:.3} µs per hash", native.0);
    for (name, backend, model) in [
        ("interpreter", PvmBackend::ForceInterpreter, MemoryModel::Sparse),
        ("JIT", PvmBackend::ForceRecompiler, MemoryModel::Auto),
    ] {
        let prepared = PreparedProgram::new_with_backend(&spi, backend).unwrap();
        let run = |k: u64| {
            let mut best = Duration::MAX;
            let mut output = Vec::new();
            for _ in 0..5 {
                let mut machine = Machine::load_prepared(&prepared, &k.to_le_bytes(), 1 << 50, model).unwrap();
                let started = Instant::now();
                let exit = machine.try_resume().unwrap();
                best = best.min(started.elapsed());
                assert_eq!(exit, ExitReason::Halt);
                output = machine.finish(exit).output_bounded(32).unwrap();
            }
            (best, output)
        };
        let (one, _) = run(1);
        let (many, output) = run(n);
        assert_eq!(output, native.1, "PVM and native hashes differ");
        let per = (us(many) - us(one)) / (n - 1) as f64;
        println!("PVM {name}: {per:.2} µs per hash ({:.0}× native)", per / native.0);
    }
}

fn main() {
    let mode = std::env::args().nth(1).unwrap_or_default();
    let arg = |i: usize| std::env::args().nth(i);
    match mode.as_str() {
        "table" => table(
            arg(2).and_then(|r| r.parse().ok()).unwrap_or(1_000_000),
            arg(3).and_then(|d| d.parse().ok()).unwrap_or(0),
        ),
        "table-lsm" => table_lsm(arg(2).and_then(|r| r.parse().ok()).unwrap_or(1_000_000)),
        "log" => {
            for entries in [1, 64, 1024] {
                log_appends(entries);
            }
        }
        "tree" => tree(
            arg(2).and_then(|k| k.parse().ok()).unwrap_or(1_000_000),
            arg(3).and_then(|b| b.parse().ok()).unwrap_or(64),
        ),
        "hash" => pvm_hash(&arg(2).expect("guest elf")),
        _ => eprintln!(
            "usage: s4-bench table <rows> [durable every] | table-lsm <rows> | tree <keys> <bits> | hash <guest.elf>"
        ),
    }
}
