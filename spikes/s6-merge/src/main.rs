//! Merge-lane apply cost as history grows: the current merkle-crdt
//! `MerkleCrdt` (which re-validates the whole DAG and rebuilds state from
//! every node on each sync, and clones state on each local operation)
//! versus an incremental replica that validates and applies only the
//! fetched nodes and derives its new roots from them.
//!
//! Workload: a last-writer-wins map. A replica holds a history of H
//! operations; a peer adds k operations on top and the replica syncs them.

use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, Instant};

use merkle_crdt::sync::fetch_missing;
use merkle_crdt::{Cid, DagNode, Encode, Hasher, MemStore, MerkleClock, MerkleCrdt, Payload, Store};

struct Blake2b;

impl Hasher for Blake2b {
    type Output = [u8; 32];
    fn hash(data: &[u8]) -> [u8; 32] {
        blake2b_simd::Params::new().hash_length(32).hash(data).as_bytes().try_into().unwrap()
    }
}

/// Set `key` to `value` at Lamport time `time`, ties broken by `replica`.
#[derive(Clone, Debug)]
struct Put {
    key: u64,
    value: u64,
    time: u64,
    replica: u8,
}

impl Encode for Put {
    fn encode_to(&self, buf: &mut Vec<u8>) {
        buf.extend_from_slice(&self.key.to_le_bytes());
        buf.extend_from_slice(&self.value.to_le_bytes());
        buf.extend_from_slice(&self.time.to_le_bytes());
        buf.push(self.replica);
    }
}

impl Payload for Put {
    type State = HashMap<u64, (u64, u8, u64)>;
    fn apply(state: &mut Self::State, op: &Self) {
        let entry = state.entry(op.key).or_insert((0, 0, 0));
        if (op.time, op.replica) > (entry.0, entry.1) {
            *entry = (op.time, op.replica, op.value);
        }
    }
}

type Store_ = MemStore<Blake2b, Put>;
type Current = MerkleCrdt<Blake2b, Put, Store_>;

/// The incremental replica: state, store and roots move only by the nodes
/// a sync fetches.
struct Incremental {
    store: Store_,
    roots: BTreeSet<Cid<Blake2b>>,
    state: HashMap<u64, (u64, u8, u64)>,
}

impl Incremental {
    fn apply(&mut self, op: Put) -> Cid<Blake2b> {
        let node = DagNode::new(op, std::mem::take(&mut self.roots));
        let cid = node.cid();
        Put::apply(&mut self.state, &node.payload);
        self.store.put(cid.clone(), node).unwrap();
        self.roots.insert(cid.clone());
        cid
    }

    fn sync(&mut self, remote_root: &Cid<Blake2b>, remote: &Store_) {
        // Fetched nodes arrive topologically sorted, oldest first, each
        // already checked against its CID. Their ancestors outside the set
        // are already applied here, so applying them in order is causal.
        let missing = fetch_missing(remote_root, &self.store, remote).unwrap();
        if missing.is_empty() {
            return;
        }
        for (_, node) in &missing {
            // A local root that a fetched node points to is no longer a head.
            for child in &node.children {
                self.roots.remove(child);
            }
            Put::apply(&mut self.state, &node.payload);
        }
        self.roots.insert(remote_root.clone());
        self.store.put_batch(missing).unwrap();
    }
}

fn op(i: u64, replica: u8) -> Put {
    let key = i.wrapping_mul(0x9e37_79b9_7f4a_7c15) % 100_000;
    Put { key, value: i, time: i + 1, replica }
}

/// A history of `h` operations, as a chain with a concurrent branch merged
/// every 64 operations.
fn history(h: u64) -> (Store_, BTreeSet<Cid<Blake2b>>, HashMap<u64, (u64, u8, u64)>) {
    let mut store = Store_::new();
    let mut clock = MerkleClock::<Blake2b>::new();
    let mut state = HashMap::new();
    let mut i = 0;
    while i < h {
        if i % 64 == 63 {
            // Two concurrent heads, merged by the next record.
            let base = clock.roots().clone();
            let side = DagNode::new(op(i, 2), base.clone());
            let side_cid = side.cid();
            Put::apply(&mut state, &side.payload);
            store.put(side_cid.clone(), side).unwrap();
            let main = op(i + 1, 1);
            Put::apply(&mut state, &main);
            clock.record(main, &mut store).unwrap();
            clock.add_roots([side_cid]);
            i += 2;
        } else {
            let main = op(i, 1);
            Put::apply(&mut state, &main);
            clock.record(main, &mut store).unwrap();
            i += 1;
        }
    }
    (store, clock.roots().clone(), state)
}

/// k new operations from a peer on top of `roots`, in a store of their own.
fn peer_ops(roots: &BTreeSet<Cid<Blake2b>>, k: u64, from: u64) -> (Store_, Cid<Blake2b>) {
    let mut store = Store_::new();
    let mut heads = roots.clone();
    let mut last = None;
    for j in 0..k {
        let node = DagNode::new(op(from + j, 3), std::mem::take(&mut heads));
        let cid = node.cid();
        store.put(cid.clone(), node).unwrap();
        heads.insert(cid.clone());
        last = Some(cid);
    }
    (store, last.unwrap())
}

fn copy_store(from: &Store_, roots: &BTreeSet<Cid<Blake2b>>) -> Store_ {
    // Walk everything reachable and copy it (MemStore has no Clone).
    let mut to = Store_::new();
    let mut stack: Vec<_> = roots.iter().cloned().collect();
    while let Some(cid) = stack.pop() {
        if to.contains(&cid).unwrap() {
            continue;
        }
        let node = from.get(&cid).unwrap().unwrap();
        stack.extend(node.children.iter().cloned());
        to.put(cid, node).unwrap();
    }
    to
}

fn us(d: Duration) -> f64 {
    d.as_secs_f64() * 1e6
}

fn main() {
    let sizes: Vec<u64> = std::env::args()
        .skip(1)
        .map(|a| a.parse().unwrap())
        .collect();
    let sizes = if sizes.is_empty() { vec![1_000, 10_000, 100_000, 1_000_000] } else { sizes };
    println!(
        "{:>9} {:>22} {:>22} {:>20} {:>22} {:>22}",
        "history", "current: sync 1 op", "current: sync 100 ops", "current: local op",
        "incremental: sync 1", "incremental: sync 100"
    );
    for h in sizes {
        let (store, roots, state) = history(h);

        // Current library: recovering a replica materializes once; every
        // sync re-validates and re-materializes.
        let mut current = Current::from_roots(copy_store(&store, &roots), roots.iter().cloned()).unwrap();
        assert_eq!(current.state(), &state);
        let samples = if h >= 1_000_000 { 2 } else { 5 };
        let mut sync_1 = Vec::new();
        let mut sync_100 = Vec::new();
        let mut local = Vec::new();
        let mut next = h + 10;
        for _ in 0..samples {
            let heads = current.roots().clone();
            let (peer, root) = peer_ops(&heads, 1, next);
            next += 1;
            let started = Instant::now();
            current.sync(&root, &peer).unwrap();
            sync_1.push(started.elapsed());
            let heads = current.roots().clone();
            let (peer, root) = peer_ops(&heads, 100, next);
            next += 100;
            let started = Instant::now();
            current.sync(&root, &peer).unwrap();
            sync_100.push(started.elapsed() / 100);
            let started = Instant::now();
            current.apply(op(next, 1)).unwrap();
            local.push(started.elapsed());
            next += 1;
        }

        // Incremental replica on the same history.
        let mut inc = Incremental { store: copy_store(&store, &roots), roots: roots.clone(), state: state.clone() };
        let mut inc_1 = Vec::new();
        let mut inc_100 = Vec::new();
        let mut next = h + 10;
        for _ in 0..200 {
            let (peer, root) = peer_ops(&inc.roots, 1, next);
            next += 1;
            let started = Instant::now();
            inc.sync(&root, &peer);
            inc_1.push(started.elapsed());
            let (peer, root) = peer_ops(&inc.roots, 100, next);
            next += 100;
            let started = Instant::now();
            inc.sync(&root, &peer);
            inc_100.push(started.elapsed() / 100);
            inc.apply(op(next, 1));
            next += 1;
        }
        // Both replicas saw the same peer operations in the same order for the
        // first `samples` rounds; check convergence against a rebuild.
        let rebuilt = Current::from_roots(copy_store(&inc.store, &inc.roots), inc.roots.iter().cloned()).unwrap();
        assert_eq!(rebuilt.state(), &inc.state, "incremental state diverged from a full rebuild");

        let median = |mut v: Vec<Duration>| {
            v.sort();
            us(v[v.len() / 2])
        };
        println!(
            "{h:>9} {:>19.1} µs {:>19.1} µs {:>17.1} µs {:>19.2} µs {:>19.2} µs",
            median(sync_1),
            median(sync_100),
            median(local),
            median(inc_1),
            median(inc_100),
        );
    }
}
