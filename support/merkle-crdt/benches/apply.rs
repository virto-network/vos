//! The cost of applying a node onto a history of 1k, 100k and 1M
//! operations: one node fetched alone, a batch of 100, and a local
//! operation, each signed and checked, on the in-memory store and on fjall.
//! The CRDT is a last-writer-wins map over 100,000 keys.
//!
//! `cargo bench -p merkle-crdt --bench apply [-- SIZES...]`; the fjall runs
//! write under `$TMPDIR`.

#[path = "../tests/common/mod.rs"]
mod common;

use std::collections::BTreeSet;
use std::time::{Duration, Instant};

use common::{H, key};
use ed25519_dalek::SigningKey;
use fjall::Database;
use merkle_crdt::{Cid, Event, FjallStore, Hasher, MemStore, Node, Replica, Rows, Store, validate};

type Op = (u64, u64);

fn lww(event: Event<'_, H, Op>, rows: &mut dyn Rows) {
    let (key, value) = *event.ops;
    let row = key.to_be_bytes();
    let mut write = [0u8; 48];
    write[..8].copy_from_slice(&event.seq.to_be_bytes());
    write[8..40].copy_from_slice(&event.author.0);
    write[40..].copy_from_slice(&value.to_le_bytes());
    if rows.read(&row).is_none_or(|old| old[..] < write[..]) {
        rows.write(&row, Some(&write));
    }
}

fn op(i: u64) -> Op {
    (i.wrapping_mul(0x9e37_79b9_7f4a_7c15) % 100_000, i)
}

/// Signs nodes onto a history: three authors in turn, each after every
/// head and its own previous node, with a fourth author's node concurrent
/// to them every 64 operations.
struct Writer {
    keys: Vec<SigningKey>,
    latest: Vec<Option<(u64, Cid<H>)>>,
    heads: BTreeSet<Cid<H>>,
    next: u64,
}

impl Writer {
    fn new() -> Self {
        Self {
            keys: (0..5).map(key).collect(),
            latest: vec![None; 5],
            heads: BTreeSet::new(),
            next: 0,
        }
    }

    fn sign(&mut self, author: usize) -> Vec<u8> {
        let mut parents = self.heads.clone();
        let seq = match &self.latest[author] {
            Some((seq, previous)) => {
                parents.insert(previous.clone());
                seq + 1
            }
            None => 0,
        };
        let node = Node::<H, Op>::sign(&self.keys[author], seq, op(self.next), parents);
        self.next += 1;
        let bytes = node.to_bytes();
        let cid = Cid(H::hash(&bytes));
        self.heads = BTreeSet::from([cid.clone()]);
        self.latest[author] = Some((seq, cid));
        bytes
    }

    fn history(&mut self, count: u64) -> Vec<Vec<u8>> {
        let mut nodes = Vec::with_capacity(count as usize);
        while nodes.len() < count as usize {
            if self.next % 64 == 63 {
                let heads = self.heads.clone();
                nodes.push(self.sign(3));
                let side = std::mem::replace(&mut self.heads, heads);
                nodes.push(self.sign((self.next % 3) as usize));
                self.heads.extend(side);
            } else {
                nodes.push(self.sign((self.next % 3) as usize));
            }
        }
        nodes
    }

    /// Nodes another device adds on top of `heads`.
    fn peer(&mut self, heads: &BTreeSet<Cid<H>>, count: usize) -> Vec<Vec<u8>> {
        self.heads = heads.clone();
        (0..count).map(|_| self.sign(4)).collect()
    }
}

fn median(mut samples: Vec<Duration>) -> f64 {
    samples.sort();
    samples[samples.len() / 2].as_secs_f64() * 1e6
}

struct Row {
    store: &'static str,
    history: u64,
    bulk: f64,
    one: f64,
    hundred: f64,
    checks: f64,
    local: f64,
}

fn measure<S: Store<H>>(
    store: &'static str,
    history: u64,
    nodes: &[Vec<u8>],
    mut replica: Replica<H, Op, S>,
) -> Row {
    let started = Instant::now();
    for batch in nodes.chunks(10_000) {
        replica.ingest(batch.to_vec(), None, &mut lww).unwrap();
    }
    let bulk = started.elapsed().as_secs_f64() * 1e6 / nodes.len() as f64;
    assert_eq!(replica.held(), 0);

    let mut peer = Writer::new();
    let local = key(20);
    let (mut one, mut hundred, mut checks, mut locals) =
        (Vec::new(), Vec::new(), Vec::new(), Vec::new());
    for _ in 0..100 {
        let batch = peer.peer(replica.heads(), 1);
        let started = Instant::now();
        replica.ingest(batch, None, &mut lww).unwrap();
        one.push(started.elapsed());

        let batch = peer.peer(replica.heads(), 100);
        let started = Instant::now();
        for bytes in &batch {
            validate::<H, Op>(bytes).unwrap();
        }
        checks.push(started.elapsed() / 100);
        let started = Instant::now();
        replica.ingest(batch, None, &mut lww).unwrap();
        hundred.push(started.elapsed() / 100);

        let started = Instant::now();
        replica.record(&local, op(peer.next), &mut lww).unwrap();
        locals.push(started.elapsed());
    }
    Row {
        store,
        history,
        bulk,
        one: median(one),
        hundred: median(hundred),
        checks: median(checks),
        local: median(locals),
    }
}

fn main() {
    let sizes: Vec<u64> = std::env::args()
        .skip(1)
        .filter_map(|arg| arg.parse().ok())
        .collect();
    let sizes = if sizes.is_empty() {
        vec![1_000, 100_000, 1_000_000]
    } else {
        sizes
    };

    // `checks`: the stateless checks alone (decoding, canonical form, CID,
    // strict signature) of the batches of 100, a node; the rest of
    // `sync 100` is the replica's own work.
    println!(
        "{:>7} {:>9} {:>14} {:>14} {:>16} {:>14} {:>14}",
        "store", "history", "bulk/node", "sync 1", "sync 100 /node", "checks", "local op"
    );

    let dir = tempfile::tempdir().unwrap();
    for history in sizes {
        let nodes = Writer::new().history(history);
        let mut rows = vec![measure(
            "memory",
            history,
            &nodes,
            Replica::open(MemStore::new()).unwrap(),
        )];
        let db = Database::builder(dir.path().join(history.to_string()))
            .open()
            .unwrap();
        let store = FjallStore::open(&db, "bench").unwrap();
        rows.push(measure(
            "fjall",
            history,
            &nodes,
            Replica::open(store).unwrap(),
        ));
        for row in rows {
            println!(
                "{:>7} {:>9} {:>11.1} µs {:>11.1} µs {:>13.1} µs {:>11.1} µs {:>11.1} µs",
                row.store, row.history, row.bulk, row.one, row.hundred, row.checks, row.local
            );
        }
    }
}
