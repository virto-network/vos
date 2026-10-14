//! Models, stores and key shapes the tests share.

use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};

use proptest::prelude::*;
use vos_tree::keys;
use vos_tree::{
    Blake2b, Child, Entry, Error, Hash, Leaf, MemStore, Node, NodeStore, branch_hash, leaf_hash,
    reachable, root, salt, value_hash,
};

pub const H: Blake2b = Blake2b;

/// The leaves a tree should hold, by key.
pub type Model = BTreeMap<Vec<u8>, Leaf>;

/// A write: a leaf row to put at a key, or `None` to delete it.
pub type Write = (Vec<u8>, Option<Leaf>);

/// The leaf row a version with seed `version` writes at `key` for `value`.
pub fn leaf(key: &[u8], version: u8, value: &[u8]) -> Leaf {
    let salt = salt(&H, &[version; 32], key);
    Leaf {
        salt,
        value_hash: value_hash(&H, &salt, value),
    }
}

/// The writes as a proof's update takes them: values' commitments.
pub fn commitments(writes: &[Write]) -> Vec<(Vec<u8>, Option<Hash>)> {
    writes
        .iter()
        .map(|(key, leaf)| (key.clone(), leaf.map(|leaf| leaf.value_hash)))
        .collect()
}

/// The root of `model`'s tree, from scratch.
pub fn scratch(model: &Model) -> Hash {
    let leaves: Vec<(&[u8], Hash)> = model
        .iter()
        .map(|(k, l)| (k.as_slice(), l.value_hash))
        .collect();
    root(&H, &leaves)
}

pub fn apply(model: &mut Model, writes: &[Write]) {
    for (key, leaf) in writes {
        match leaf {
            Some(leaf) => model.insert(key.clone(), *leaf),
            None => model.remove(key),
        };
    }
}

/// A store holding `model`'s tree, built in one update.
pub fn store_of(model: &Model) -> MemStore {
    let mut store = MemStore::default();
    let writes: Vec<Write> = model.iter().map(|(k, l)| (k.clone(), Some(*l))).collect();
    vos_tree::update(&H, &mut store, &writes).unwrap();
    store
}

/// Check that `store` holds the tree over `model` and no other row: the
/// rows its top reaches are all it holds, each reference's hash and place
/// agree with the row it names, and the leaves are the model's.
pub fn check(store: &MemStore, model: &Model) {
    let rows = reachable(store).unwrap();
    let nodes: BTreeSet<_> = rows.nodes.iter().cloned().collect();
    assert_eq!(nodes.len(), rows.nodes.len(), "each branch reached once");
    let stored: BTreeSet<_> = store.nodes.keys().cloned().collect();
    assert_eq!(nodes, stored, "no node row off the tree");
    let leaves: Vec<_> = store.leaves.keys().cloned().collect();
    assert_eq!(rows.leaves, leaves, "no leaf row off the tree");
    assert_eq!(&store.leaves, model);
    assert_eq!(
        store.nodes.len() + 1,
        model.len().max(1),
        "a branch per pair"
    );

    let mut stack: Vec<(Child, Option<u16>)> =
        store.top.clone().into_iter().map(|c| (c, None)).collect();
    while let Some((child, above)) = stack.pop() {
        match child {
            Child::Leaf { key, hash } => {
                let value_hash = model[&key].value_hash;
                assert_eq!(hash, leaf_hash(&H, &key, &value_hash), "a leaf's hash");
            }
            Child::Branch {
                level,
                prefix,
                hash,
            } => {
                assert!(above.is_none_or(|above| above < level), "levels increase");
                let Node { left, right } = &store.nodes[&(level, prefix.clone())];
                assert_eq!(hash, branch_hash(&H, level, left.hash(), right.hash()));
                for (side, child) in [left, right].into_iter().enumerate() {
                    let below = match child {
                        Child::Leaf { key, .. } => key,
                        Child::Branch { prefix, .. } => prefix,
                    };
                    assert_eq!(place(below, level), prefix, "a branch's place");
                    assert_eq!(bit(below, level), side, "a child's side");
                }
                stack.push((left.clone(), Some(level)));
                stack.push((right.clone(), Some(level)));
            }
        }
    }
}

pub fn bit(key: &[u8], level: u16) -> usize {
    let level = usize::from(level);
    key.get(level / 8)
        .map_or(0, |b| usize::from((b >> (7 - level % 8)) & 1))
}

/// The first `level` bits of `key`, as a branch's place.
fn place(key: &[u8], level: u16) -> Vec<u8> {
    let level = usize::from(level);
    let mut prefix = key[..level.div_ceil(8)].to_vec();
    if !level.is_multiple_of(8) {
        *prefix.last_mut().unwrap() &= 0xFF << (8 - level % 8);
    }
    prefix
}

/// A store whose every read in an update must come before the update's
/// first write.
#[derive(Default)]
pub struct Ordered {
    pub inner: MemStore,
    wrote: Cell<bool>,
}

impl Ordered {
    pub fn update(&mut self, writes: &[Write]) -> Hash {
        self.wrote.set(false);
        vos_tree::update(&H, self, writes).unwrap()
    }

    fn read(&self) {
        assert!(!self.wrote.get(), "a read after a write");
    }
}

impl NodeStore for Ordered {
    type Error = Error;

    fn top(&self) -> Result<Option<Child>, Self::Error> {
        self.read();
        self.inner.top()
    }
    fn node(&self, level: u16, prefix: &[u8]) -> Result<Option<Node>, Self::Error> {
        self.read();
        self.inner.node(level, prefix)
    }
    fn leaf(&self, key: &[u8]) -> Result<Option<Leaf>, Self::Error> {
        self.read();
        self.inner.leaf(key)
    }
    fn set_top(&mut self, top: Option<Child>) -> Result<(), Self::Error> {
        self.wrote.set(true);
        self.inner.set_top(top)
    }
    fn put_node(&mut self, level: u16, prefix: &[u8], node: Node) -> Result<(), Self::Error> {
        self.wrote.set(true);
        self.inner.put_node(level, prefix, node)
    }
    fn delete_node(&mut self, level: u16, prefix: &[u8]) -> Result<(), Self::Error> {
        self.wrote.set(true);
        self.inner.delete_node(level, prefix)
    }
    fn put_leaf(&mut self, key: &[u8], leaf: Leaf) -> Result<(), Self::Error> {
        self.wrote.set(true);
        self.inner.put_leaf(key, leaf)
    }
    fn delete_leaf(&mut self, key: &[u8]) -> Result<(), Self::Error> {
        self.wrote.set(true);
        self.inner.delete_leaf(key)
    }
}

/// A raw key over bytes at the edges of the escape's order.
pub fn raw_key() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(
        prop::sample::select(vec![0x00u8, 0x01, 0x7F, 0x80, 0xFF]),
        0..5,
    )
}

/// A row key of one of two maps: `a/` ordered, `b/` hashed.
pub fn row_key(hashed: bool, raw: &[u8]) -> Vec<u8> {
    if hashed {
        [b"b/".as_slice(), &keys::hashed(&H, raw)].concat()
    } else {
        [b"a/".as_slice(), &keys::ordered(raw)].concat()
    }
}

/// The row keys a case draws its writes from.
pub fn pool() -> impl Strategy<Value = Vec<Vec<u8>>> {
    prop::collection::vec((any::<bool>(), raw_key()), 1..24).prop_map(|keys| {
        let keys: BTreeSet<_> = keys.iter().map(|(h, raw)| row_key(*h, raw)).collect();
        keys.into_iter().collect()
    })
}

/// Batches of writes, as indices into a pool and a value or a delete.
pub fn batches() -> impl Strategy<Value = Vec<Vec<(usize, Option<u8>)>>> {
    let write = (any::<usize>(), prop::option::weighted(0.7, any::<u8>()));
    prop::collection::vec(prop::collection::vec(write, 1..12), 1..6)
}

/// One batch's writes on `pool` by `version`, in key order, the last
/// write to a key winning.
pub fn writes(pool: &[Vec<u8>], batch: &[(usize, Option<u8>)], version: u8) -> Vec<Write> {
    let writes: BTreeMap<_, _> = batch
        .iter()
        .map(|&(at, value)| {
            let key = &pool[at % pool.len()];
            (key.clone(), value.map(|v| leaf(key, version, &[v])))
        })
        .collect();
    writes.into_iter().collect()
}

/// The claims a model makes about `keys`.
pub fn claims(model: &Model, keys: &[Vec<u8>]) -> Vec<(Vec<u8>, Option<Hash>)> {
    keys.iter()
        .map(|key| (key.clone(), model.get(key).map(|leaf| leaf.value_hash)))
        .collect()
}

/// The rows a model holds in `[from, to)`.
pub fn rows(model: &Model, from: &[u8], to: Option<&[u8]>) -> Vec<(Vec<u8>, Hash)> {
    model
        .iter()
        .filter(|(key, _)| key.as_slice() >= from && to.is_none_or(|to| key.as_slice() < to))
        .map(|(key, leaf)| (key.clone(), leaf.value_hash))
        .collect()
}

/// The index past the subtree whose first entry is `entries[at]`.
pub fn subtree_end(entries: &[Entry], mut at: usize) -> usize {
    let mut open = 1;
    while open > 0 {
        open -= 1;
        if let Entry::Branch(_) = entries[at] {
            open += 2;
        }
        at += 1;
    }
    at
}

/// Tampered copies of a proof's entries, each named.
pub fn tampered(entries: &[Entry]) -> Vec<(&'static str, Vec<Entry>)> {
    let mut out = Vec::new();
    if let Some(at) = entries.iter().position(|e| matches!(e, Entry::Hash(_))) {
        let mut copy = entries.to_vec();
        let Entry::Hash(hash) = &mut copy[at] else {
            unreachable!()
        };
        hash[7] ^= 0x10;
        out.push(("a flipped sibling", copy));
    }
    for (at, entry) in entries.iter().enumerate() {
        let Entry::Branch(level) = *entry else {
            continue;
        };
        let mid = subtree_end(entries, at + 1);
        let end = subtree_end(entries, mid);
        let mut copy = entries[..=at].to_vec();
        copy.extend_from_slice(&entries[mid..end]);
        copy.extend_from_slice(&entries[at + 1..mid]);
        copy.extend_from_slice(&entries[end..]);
        out.push(("swapped children", copy));
        for wrong in [level.wrapping_add(1), level.wrapping_sub(1)] {
            let mut copy = entries.to_vec();
            copy[at] = Entry::Branch(wrong);
            out.push(("a wrong level", copy));
        }
    }
    let leaves: Vec<usize> = (0..entries.len())
        .filter(|&at| matches!(entries[at], Entry::Leaf { .. }))
        .collect();
    for pair in leaves.windows(2) {
        let mut copy = entries.to_vec();
        copy.swap(pair[0], pair[1]);
        out.push(("out-of-order leaves", copy));
    }
    if let Some(&at) = leaves.first() {
        let mut copy = entries.to_vec();
        let Entry::Leaf { value_hash, .. } = &mut copy[at] else {
            unreachable!()
        };
        value_hash[0] ^= 1;
        out.push(("another commitment", copy));
        let mut copy = entries.to_vec();
        copy.remove(at);
        out.push(("a leaf left out", copy));
    }
    out
}
