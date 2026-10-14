//! What an update costs on a tree of hashed keys: hashes, node rows
//! rewritten, and µs per update on the in-memory store, single and in
//! batches of 10,000 (S4's committed-roots measurement, on this crate).
//!
//! `cargo bench -p vos-tree --bench update -- [keys …]`, 1M and 10M keys
//! by default.

use std::cell::Cell;
use std::time::{Duration, Instant};

use vos_tree::{
    Blake2b, Child, Error, Hash, Hasher, Leaf, MemStore, Node, NodeStore, keys, salt, update,
    value_hash,
};

/// BLAKE2b, counted.
#[derive(Default)]
struct Counting {
    hashes: Cell<u64>,
}

impl Hasher for Counting {
    fn hash(&self, tag: &[u8], parts: &[&[u8]]) -> Hash {
        self.hashes.set(self.hashes.get() + 1);
        Blake2b.hash(tag, parts)
    }
}

/// The in-memory store, its node row writes counted and its time taken.
#[derive(Default)]
struct Counted {
    inner: MemStore,
    rows: u64,
    spent: Cell<Duration>,
}

impl Counted {
    fn timed<T>(&self, op: impl FnOnce() -> T) -> T {
        let started = Instant::now();
        let out = op();
        self.spent.set(self.spent.get() + started.elapsed());
        out
    }
}

impl NodeStore for Counted {
    type Error = Error;

    fn top(&self) -> Result<Option<Child>, Error> {
        self.timed(|| self.inner.top())
    }
    fn node(&self, level: u16, prefix: &[u8]) -> Result<Option<Node>, Error> {
        self.timed(|| self.inner.node(level, prefix))
    }
    fn leaf(&self, key: &[u8]) -> Result<Option<Leaf>, Error> {
        self.timed(|| self.inner.leaf(key))
    }
    fn set_top(&mut self, top: Option<Child>) -> Result<(), Error> {
        let started = Instant::now();
        let out = self.inner.set_top(top);
        self.spent.set(self.spent.get() + started.elapsed());
        out
    }
    fn put_node(&mut self, level: u16, prefix: &[u8], node: Node) -> Result<(), Error> {
        self.rows += 1;
        let started = Instant::now();
        let out = self.inner.put_node(level, prefix, node);
        self.spent.set(self.spent.get() + started.elapsed());
        out
    }
    fn delete_node(&mut self, level: u16, prefix: &[u8]) -> Result<(), Error> {
        self.inner.delete_node(level, prefix)
    }
    fn put_leaf(&mut self, key: &[u8], leaf: Leaf) -> Result<(), Error> {
        let started = Instant::now();
        let out = self.inner.put_leaf(key, leaf);
        self.spent.set(self.spent.get() + started.elapsed());
        out
    }
    fn delete_leaf(&mut self, key: &[u8]) -> Result<(), Error> {
        self.inner.delete_leaf(key)
    }
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

/// Row `i`'s key: a map's prefix and the hashed transform of a u64.
fn key(i: u64) -> Vec<u8> {
    [b"c/".as_slice(), &keys::hashed(&Blake2b, &i.to_be_bytes())].concat()
}

/// The writes of `version` to `rows`, in key order.
fn writes(rows: impl Iterator<Item = u64>, version: u8) -> Vec<(Vec<u8>, Option<Leaf>)> {
    let mut writes: Vec<_> = rows
        .map(|i| {
            let key = key(i);
            let salt = salt(&Blake2b, &[version; 32], &key);
            let leaf = Leaf {
                salt,
                value_hash: value_hash(&Blake2b, &salt, &i.to_le_bytes()),
            };
            (key, Some(leaf))
        })
        .collect();
    writes.sort_by(|a, b| a.0.cmp(&b.0));
    writes.dedup_by(|a, b| a.0 == b.0);
    writes
}

fn tree(rows: u64) {
    let started = Instant::now();
    let mut store = Counted::default();
    let chunk = 1_000_000;
    for from in (0..rows).step_by(chunk as usize) {
        update(
            &Blake2b,
            &mut store,
            &writes(from..(from + chunk).min(rows), 0),
        )
        .unwrap();
    }
    println!(
        "{rows} hashed keys: built in {:.1} s, {} node rows",
        started.elapsed().as_secs_f64(),
        store.inner.nodes.len()
    );
    let mut rng = XorShift(0x9e37_79b9_7f4a_7c15);
    for batch in [1u64, 10_000] {
        let rounds = (20_000 / batch).max(3);
        let hasher = Counting::default();
        let (mut elapsed, mut updates) = (Duration::ZERO, 0);
        store.rows = 0;
        store.spent.set(Duration::ZERO);
        for round in 0..rounds {
            let writes = writes((0..batch).map(|_| rng.next() % rows), 1 + round as u8);
            let started = Instant::now();
            update(&hasher, &mut store, &writes).unwrap();
            elapsed += started.elapsed();
            updates += writes.len() as u64;
        }
        let per = updates as f64;
        println!(
            "  batch {batch:>5}: {:>5.1} hashes and {:>5.1} node rows per update, \
             {:>6.2} µs per update, {:>6.2} µs of it in the store",
            hasher.hashes.get() as f64 / per,
            store.rows as f64 / per,
            elapsed.as_secs_f64() * 1e6 / per,
            store.spent.get().as_secs_f64() * 1e6 / per,
        );
    }
}

/// One branch's hash: a tag, a level and two children.
fn hash_cost() {
    let n = 1_000_000;
    let (mut left, right) = ([7u8; 32], [9u8; 32]);
    let started = Instant::now();
    for level in 0..n {
        left = vos_tree::branch_hash(&Blake2b, level as u16, &left, &right);
    }
    std::hint::black_box(left);
    println!(
        "a branch hash: {:.3} µs",
        started.elapsed().as_secs_f64() * 1e6 / n as f64
    );
}

fn main() {
    let sizes: Vec<u64> = std::env::args()
        .skip(1)
        .filter_map(|arg| arg.parse().ok())
        .collect();
    hash_cost();
    let sizes = if sizes.is_empty() {
        vec![1_000_000, 10_000_000]
    } else {
        sizes
    };
    for rows in sizes {
        tree(rows);
    }
}
