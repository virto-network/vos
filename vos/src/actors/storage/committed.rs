//! Committed storage: a map whose whole content is bound by a sparse-
//! Merkle root, maintained *incrementally* as ordinary storage rows.
//!
//! The hash math lives in [`crate::zk::state`] (fixed-depth SMT,
//! depth = 8 × key width, cipher-clerk-compatible conventions); this
//! module is the row-backed representation that keeps the root current
//! across dispatches without ever touching more than the branch path
//! of a mutated key.
//!
//! ## Representation
//!
//! The full fixed-depth tree is mostly empty spines: a subtree holding
//! a single leaf hashes up through nothing but empty-chain siblings,
//! so nothing below its top needs storing. Rows exist only where the
//! key set actually branches (the radix structure of the keys):
//!
//! - value rows `…v/<key>` — the entry's encoded value, exactly like
//!   [`StorageMap`](super::StorageMap); the leaf hash commits these
//!   bytes. Point `get` stays a single row read.
//! - node rows `…n<level u16 BE><prefix>` — one per *branching point*:
//!   a node at `(level, prefix)` covers the keys sharing `prefix`'s
//!   first `level` bits and splits on bit `level`. Every stored node
//!   has two non-empty children (delete collapses one-child nodes), so
//!   the row count is `len − 1` and a mutation touches only the
//!   branching points along its key — O(log n) rows, not O(depth).
//! - the root row `…r` — `[count][root hash][top ref]`.
//!
//! A child reference names either a leaf (key + leaf hash) or a
//! deeper branch node (level + prefix + memoized subtree hash); the
//! levels in between are recomputed as empty spines. The structure is
//! a pure function of the key set — replicas converge byte-identically
//! regardless of insertion order — and an in-order walk of the node
//! rows yields keys ascending, so the tree doubles as the ordered
//! index (there are no separate index pages here).

use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::actors::codec::{Decode, Encode};
use crate::zk::state::{self, SmtParams};

use super::{Core, FixedKey, decode_or_panic, overlay_load, overlay_store};

/// A child slot of a branch node (or the tree's top slot in the root
/// row): nothing, a single leaf, or a deeper branch node whose
/// subtree hash is memoized alongside its address.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Ref {
    Empty,
    Leaf { key: Vec<u8>, hash: [u8; 32] },
    Branch { level: u16, prefix: Vec<u8>, hash: [u8; 32] },
}

const REF_EMPTY: u8 = 0;
const REF_LEAF: u8 = 1;
const REF_BRANCH: u8 = 2;

impl Ref {
    fn encode_into(&self, out: &mut Vec<u8>) {
        match self {
            Ref::Empty => out.push(REF_EMPTY),
            Ref::Leaf { key, hash } => {
                out.push(REF_LEAF);
                out.extend_from_slice(key);
                out.extend_from_slice(hash);
            }
            Ref::Branch {
                level,
                prefix,
                hash,
            } => {
                out.push(REF_BRANCH);
                out.extend_from_slice(&level.to_be_bytes());
                out.extend_from_slice(prefix);
                out.extend_from_slice(hash);
            }
        }
    }

    fn decode_from(bytes: &[u8], width: usize, at: &mut usize) -> Ref {
        let tag = bytes[*at];
        *at += 1;
        match tag {
            REF_EMPTY => Ref::Empty,
            REF_LEAF => {
                let key = bytes[*at..*at + width].to_vec();
                *at += width;
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes[*at..*at + 32]);
                *at += 32;
                Ref::Leaf { key, hash }
            }
            REF_BRANCH => {
                let level = u16::from_be_bytes([bytes[*at], bytes[*at + 1]]);
                *at += 2;
                let prefix = bytes[*at..*at + width].to_vec();
                *at += width;
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes[*at..*at + 32]);
                *at += 32;
                Ref::Branch {
                    level,
                    prefix,
                    hash,
                }
            }
            other => panic!("corrupt committed-map node row — unknown ref tag {other}"),
        }
    }
}

/// The hash of the subtree containing `r`'s content, lifted to
/// `at_level` (MSB-first bits fixed above it): the memoized hash rides
/// up through the all-empty levels in between as a spine.
fn ref_subtree_hash(p: &SmtParams, chain: &[[u8; 32]], r: &Ref, at_level: usize) -> [u8; 32] {
    let depth = p.depth();
    match r {
        Ref::Empty => chain[depth - at_level],
        Ref::Leaf { key, hash } => state::spine_hash(p, chain, key, *hash, 0, depth - at_level),
        Ref::Branch {
            level,
            prefix,
            hash,
        } => state::spine_hash(
            p,
            chain,
            prefix,
            *hash,
            depth - *level as usize,
            depth - at_level,
        ),
    }
}

/// First MSB-first bit where `a` and `b` differ. Caller guarantees the
/// keys are distinct.
fn first_diff_level(a: &[u8], b: &[u8]) -> usize {
    for (i, (x, y)) in a.iter().zip(b).enumerate() {
        if x != y {
            return i * 8 + (x ^ y).leading_zeros() as usize;
        }
    }
    unreachable!("first_diff_level on equal keys")
}

/// First bit `< limit` where `key` disagrees with `prefix`, if any.
fn diverge_before(key: &[u8], prefix: &[u8], limit: usize) -> Option<usize> {
    for l in 0..limit {
        if state::level_bit(key, l) != state::level_bit(prefix, l) {
            return Some(l);
        }
    }
    None
}

/// `key`'s first `level` bits, zero-padded to full width — the
/// canonical prefix for a node row at `level`.
fn prefix_of(key: &[u8], level: usize) -> Vec<u8> {
    let mut out = alloc::vec![0u8; key.len()];
    let full = level / 8;
    out[..full].copy_from_slice(&key[..full]);
    if level % 8 != 0 {
        let mask = !(0xffu8 >> (level % 8));
        out[full] = key[full] & mask;
    }
    out
}

/// A key-ordered map committed by an incrementally-maintained SMT
/// root. Same point-read profile as [`StorageMap`](super::StorageMap);
/// mutations additionally rewrite the branch nodes along the key's
/// path. Iteration walks the tree in order — the node rows *are* the
/// ordered index (and the authentication-path material).
pub struct CommittedMap<K, V> {
    core: Core,
    leaf_domain: &'static [u8],
    node_domain: &'static [u8],
    /// Per-instance empty-chain cache (depth + 1 hashes) so repeated
    /// mutations in one dispatch pay the chain once. Handles archive
    /// as units, so this resets with the instance each dispatch.
    chain: Option<Vec<[u8; 32]>>,
    _marker: PhantomData<(K, V)>,
}

impl<K, V> Default for CommittedMap<K, V> {
    fn default() -> Self {
        Self {
            core: Core::uninit(),
            leaf_domain: state::VOS_LEAF_DOMAIN,
            node_domain: state::VOS_NODE_DOMAIN,
            chain: None,
            _marker: PhantomData,
        }
    }
}

super::unit_archive!(CommittedMap<K, V>);

impl<K: FixedKey, V: Encode + Decode> CommittedMap<K, V> {
    #[doc(hidden)]
    pub fn __init(&mut self, prefix: &[u8]) {
        self.core.init(prefix);
    }

    /// Init with application-owned hash domains — for trees that must
    /// reproduce roots pinned outside vos (clerk-ledger ↔ cipher-clerk).
    #[doc(hidden)]
    pub fn __init_with_domains(
        &mut self,
        prefix: &[u8],
        leaf_domain: &'static [u8],
        node_domain: &'static [u8],
    ) {
        self.core.init(prefix);
        self.leaf_domain = leaf_domain;
        self.node_domain = node_domain;
    }

    fn params(&self) -> SmtParams {
        SmtParams {
            leaf_domain: self.leaf_domain,
            node_domain: self.node_domain,
            width: K::WIDTH,
        }
    }

    fn key_bytes(key: &K) -> Vec<u8> {
        let mut out = Vec::with_capacity(K::WIDTH);
        key.write_to(&mut out);
        out
    }

    fn value_row(&self, kb: &[u8]) -> Vec<u8> {
        self.core.row(b'v', kb)
    }

    fn node_row(&self, level: u16, prefix: &[u8]) -> Vec<u8> {
        let mut suffix = Vec::with_capacity(2 + prefix.len());
        suffix.extend_from_slice(&level.to_be_bytes());
        suffix.extend_from_slice(prefix);
        self.core.row(b'n', &suffix)
    }

    fn root_row(&self) -> Vec<u8> {
        self.core.row(b'r', &[])
    }

    fn read_node(&self, level: u16, prefix: &[u8]) -> (Ref, Ref) {
        let bytes = overlay_load(&self.node_row(level, prefix))
            .expect("committed-map branch ref names a node with no row");
        let mut at = 0;
        let left = Ref::decode_from(&bytes, K::WIDTH, &mut at);
        let right = Ref::decode_from(&bytes, K::WIDTH, &mut at);
        (left, right)
    }

    fn write_node(&mut self, level: u16, prefix: &[u8], left: &Ref, right: &Ref) {
        let mut bytes = Vec::new();
        left.encode_into(&mut bytes);
        right.encode_into(&mut bytes);
        overlay_store(self.node_row(level, prefix), Some(bytes));
    }

    /// `(count, root_hash, top ref)`; an absent root row is the empty
    /// tree (its hash is materialized lazily to avoid hashing on the
    /// read path).
    fn read_root(&self) -> (u64, Option<[u8; 32]>, Ref) {
        match overlay_load(&self.root_row()) {
            None => (0, None, Ref::Empty),
            Some(bytes) => {
                let count = u64::from_le_bytes(bytes[..8].try_into().unwrap());
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&bytes[8..40]);
                let mut at = 40;
                let top = Ref::decode_from(&bytes, K::WIDTH, &mut at);
                (count, Some(hash), top)
            }
        }
    }

    fn write_root(&mut self, count: u64, hash: &[u8; 32], top: &Ref) {
        let mut bytes = Vec::with_capacity(8 + 32 + 1 + K::WIDTH + 34);
        bytes.extend_from_slice(&count.to_le_bytes());
        bytes.extend_from_slice(hash);
        top.encode_into(&mut bytes);
        overlay_store(self.root_row(), Some(bytes));
    }

    /// Number of entries (the root row's count).
    pub fn len(&self) -> u64 {
        self.read_root().0
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The committed root over the current content. The composite
    /// `anchor_kind 0x02` anchor folds these per-field roots.
    pub fn root(&self) -> [u8; 32] {
        match self.read_root() {
            (_, Some(hash), _) => hash,
            (_, None, _) => {
                let p = self.params();
                *state::empty_chain(&p).last().unwrap()
            }
        }
    }

    /// Point read — one value row, no tree traffic.
    pub fn get(&self, key: &K) -> Option<V> {
        overlay_load(&self.value_row(&Self::key_bytes(key)))
            .map(|b| decode_or_panic(&b, "CommittedMap value"))
    }

    pub fn contains(&self, key: &K) -> bool {
        overlay_load(&self.value_row(&Self::key_bytes(key))).is_some()
    }

    /// Insert or overwrite; returns `true` when the key was fresh.
    /// Writes the value row and rewrites the branch path: the leaf
    /// hash commits the value's encoded bytes, the key is committed by
    /// its tree position.
    pub fn insert(&mut self, key: &K, value: &V) -> bool {
        let encoded = value.encode();
        self.insert_encoded(key, encoded.clone(), &encoded)
    }

    /// Insert with caller-supplied leaf content — for trees whose leaf
    /// encoding is pinned outside vos (clerk-ledger's cipher-clerk
    /// parity leaves: a domain-tag byte followed by the payload). The
    /// value row still stores `value`'s own encoding; only the hash
    /// input differs. The caller owns keeping content and value in
    /// lockstep — a divergence shows up as a root that no rebuild
    /// reproduces.
    pub fn insert_with_leaf(&mut self, key: &K, value: &V, leaf_content: &[u8]) -> bool {
        self.insert_encoded(key, value.encode(), leaf_content)
    }

    fn insert_encoded(&mut self, key: &K, value_bytes: Vec<u8>, leaf_content: &[u8]) -> bool {
        let kb = Self::key_bytes(key);
        let p = self.params();
        let leaf = state::leaf_hash(&p, leaf_content);
        overlay_store(self.value_row(&kb), Some(value_bytes));
        self.update_tree(&kb, Some(leaf))
    }

    /// Remove; returns `true` when the key was present.
    pub fn remove(&mut self, key: &K) -> bool {
        let kb = Self::key_bytes(key);
        if overlay_load(&self.value_row(&kb)).is_none() {
            return false;
        }
        overlay_store(self.value_row(&kb), None);
        self.update_tree(&kb, None)
    }

    /// Ordered iteration over `(key, value)` — an in-order walk of the
    /// branch nodes; values fetch lazily one row each.
    pub fn iter(&self) -> CommittedMapIter<'_, K, V> {
        let (_, _, top) = self.read_root();
        CommittedMapIter {
            map: self,
            stack: alloc::vec![top],
        }
    }

    /// Set (`Some(leaf_hash)`) or clear (`None`) `kb`'s leaf and
    /// rewrite the branch path up to the root row. Returns whether the
    /// key-set changed (fresh insert / real removal).
    fn update_tree(&mut self, kb: &[u8], leaf: Option<[u8; 32]>) -> bool {
        let p = self.params();
        let chain = self
            .chain
            .take()
            .unwrap_or_else(|| state::empty_chain(&p));
        let (mut count, _, top) = self.read_root();

        // Walk down to the slot the key occupies (or diverges from),
        // remembering each branch node passed through.
        let mut stack: Vec<(u16, Vec<u8>, Ref, Ref, bool)> = Vec::new();
        let mut cur = top;
        // The ref that replaces the slot the walk stopped at; None
        // removes the slot (delete of a leaf). `changed` = the key SET
        // changed (fresh insert / real removal) — an overwrite is not
        // a change.
        let replacement: Option<Ref>;
        let changed: bool;
        loop {
            match cur {
                Ref::Empty => {
                    match leaf {
                        Some(hash) => {
                            count += 1;
                            changed = true;
                            replacement = Some(Ref::Leaf {
                                key: kb.to_vec(),
                                hash,
                            });
                        }
                        // Deleting an absent key: the value-row check in
                        // remove() makes this unreachable, but keep it
                        // total.
                        None => {
                            changed = false;
                            replacement = Some(Ref::Empty);
                        }
                    }
                    break;
                }
                Ref::Leaf { key: k2, hash: h2 } => {
                    if k2 == kb {
                        match leaf {
                            Some(hash) => {
                                changed = false;
                                replacement = Some(Ref::Leaf {
                                    key: k2,
                                    hash,
                                });
                            }
                            None => {
                                count -= 1;
                                changed = true;
                                replacement = None;
                            }
                        }
                        break;
                    }
                    // Distinct key in the slot: only an insert can
                    // land here (remove pre-checked the value row).
                    let hash = leaf.expect("remove reached a foreign leaf");
                    count += 1;
                    changed = true;
                    let d = first_diff_level(kb, &k2);
                    let prefix = prefix_of(kb, d);
                    let ours = Ref::Leaf {
                        key: kb.to_vec(),
                        hash,
                    };
                    let theirs = Ref::Leaf { key: k2, hash: h2 };
                    let (l, r) = if state::level_bit(kb, d) {
                        (theirs, ours)
                    } else {
                        (ours, theirs)
                    };
                    let h = state::node_hash(
                        &p,
                        &ref_subtree_hash(&p, &chain, &l, d + 1),
                        &ref_subtree_hash(&p, &chain, &r, d + 1),
                    );
                    self.write_node(d as u16, &prefix, &l, &r);
                    replacement = Some(Ref::Branch {
                        level: d as u16,
                        prefix,
                        hash: h,
                    });
                    break;
                }
                Ref::Branch {
                    level,
                    prefix,
                    hash,
                } => {
                    if let Some(d) = diverge_before(kb, &prefix, level as usize) {
                        // The key leaves the compressed spine above
                        // this node — again insert-only territory.
                        let lhash = leaf.expect("remove diverged from every stored key");
                        count += 1;
                        changed = true;
                        let new_prefix = prefix_of(kb, d);
                        let ours = Ref::Leaf {
                            key: kb.to_vec(),
                            hash: lhash,
                        };
                        let theirs = Ref::Branch {
                            level,
                            prefix,
                            hash,
                        };
                        let (l, r) = if state::level_bit(kb, d) {
                            (theirs, ours)
                        } else {
                            (ours, theirs)
                        };
                        let h = state::node_hash(
                            &p,
                            &ref_subtree_hash(&p, &chain, &l, d + 1),
                            &ref_subtree_hash(&p, &chain, &r, d + 1),
                        );
                        self.write_node(d as u16, &new_prefix, &l, &r);
                        replacement = Some(Ref::Branch {
                            level: d as u16,
                            prefix: new_prefix,
                            hash: h,
                        });
                        break;
                    }
                    let (left, right) = self.read_node(level, &prefix);
                    let side = state::level_bit(kb, level as usize);
                    cur = if side { right.clone() } else { left.clone() };
                    stack.push((level, prefix, left, right, side));
                }
            }
        }

        // Determine the ref that flows into the parent slot. A removed
        // leaf collapses its parent node: every stored node keeps two
        // non-empty children, so the sibling (leaf or whole branch)
        // lifts into the grandparent unchanged — that collapse is what
        // keeps the structure a pure function of the key set.
        let mut child = match replacement {
            Some(r) => r,
            None => match stack.pop() {
                None => Ref::Empty,
                Some((level, prefix, left, right, side)) => {
                    overlay_store(self.node_row(level, &prefix), None);
                    if side { left } else { right }
                }
            },
        };

        // Bubble the updated child ref through the remaining branch
        // nodes, rewriting each row and re-memoizing its subtree hash.
        while let Some((level, prefix, mut left, mut right, side)) = stack.pop() {
            if side {
                right = child;
            } else {
                left = child;
            }
            self.write_node(level, &prefix, &left, &right);
            let h = state::node_hash(
                &p,
                &ref_subtree_hash(&p, &chain, &left, level as usize + 1),
                &ref_subtree_hash(&p, &chain, &right, level as usize + 1),
            );
            child = Ref::Branch {
                level,
                prefix,
                hash: h,
            };
        }

        let root_hash = ref_subtree_hash(&p, &chain, &child, 0);
        self.write_root(count, &root_hash, &child);
        self.chain = Some(chain);
        changed
    }
}

/// In-order tree walk; see [`CommittedMap::iter`].
pub struct CommittedMapIter<'a, K, V> {
    map: &'a CommittedMap<K, V>,
    stack: Vec<Ref>,
}

impl<K: FixedKey, V: Encode + Decode> Iterator for CommittedMapIter<'_, K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<(K, V)> {
        loop {
            match self.stack.pop()? {
                Ref::Empty => continue,
                Ref::Leaf { key, .. } => {
                    let value = overlay_load(&self.map.value_row(&key))
                        .expect("committed-map leaf names a key with no value row");
                    return Some((
                        K::read_from(&key),
                        decode_or_panic(&value, "CommittedMap value"),
                    ));
                }
                Ref::Branch { level, prefix, .. } => {
                    let (left, right) = self.map.read_node(level, &prefix);
                    self.stack.push(right);
                    self.stack.push(left);
                }
            }
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use super::super::{end_dispatch, mock};
    use super::*;
    use crate::zk::state::{leaf_hash, root_of_sorted};
    use alloc::collections::BTreeMap;

    fn fresh() {
        mock::reset();
        let _ = end_dispatch();
    }

    fn map() -> CommittedMap<[u8; 16], u64> {
        let mut m = CommittedMap::default();
        m.__init(b"s/committed/");
        m
    }

    fn key(i: u64) -> [u8; 16] {
        let h = crate::crypto::blake2b_hash::<32>(b"cm-test-key", &[&i.to_le_bytes()]);
        let mut k = [0u8; 16];
        k.copy_from_slice(&h[..16]);
        k
    }

    /// Full-recompute reference root over a model of the content.
    fn reference_root(p: &SmtParams, model: &BTreeMap<[u8; 16], u64>) -> [u8; 32] {
        let leaves: Vec<([u8; 16], [u8; 32])> = model
            .iter()
            .map(|(k, v)| (*k, leaf_hash(p, &v.encode())))
            .collect();
        root_of_sorted(p, &leaves)
    }

    #[test]
    fn incremental_root_matches_full_recompute_through_random_ops() {
        fresh();
        let mut m = map();
        let p = m.params();
        let mut model: BTreeMap<[u8; 16], u64> = BTreeMap::new();

        // Deterministic op mix: inserts, overwrites, removes.
        for step in 0u64..200 {
            let k = key(step % 37);
            match step % 5 {
                0..=2 => {
                    let fresh_key = !model.contains_key(&k);
                    assert_eq!(m.insert(&k, &step), fresh_key, "insert freshness @{step}");
                    model.insert(k, step);
                }
                3 => {
                    let present = model.remove(&k).is_some();
                    assert_eq!(m.remove(&k), present, "remove presence @{step}");
                }
                _ => {
                    assert_eq!(m.get(&k), model.get(&k).copied(), "get parity @{step}");
                }
            }
            assert_eq!(m.len(), model.len() as u64, "count parity @{step}");
            assert_eq!(
                m.root(),
                reference_root(&p, &model),
                "incremental root diverged from full recompute @{step}"
            );
        }

        // Ordered iteration yields the model exactly.
        let walked: Vec<([u8; 16], u64)> = m.iter().collect();
        let expected: Vec<([u8; 16], u64)> = model.iter().map(|(k, v)| (*k, *v)).collect();
        assert_eq!(walked, expected, "in-order walk mismatch");
    }

    #[test]
    fn rows_are_a_pure_function_of_the_key_set() {
        // Same final content via different histories ⇒ byte-identical
        // rows (delete must collapse one-child nodes exactly).
        let build = |ops: &dyn Fn(&mut CommittedMap<[u8; 16], u64>)| {
            fresh();
            let mut m = map();
            ops(&mut m);
            mock::commit(end_dispatch());
            mock::snapshot()
        };

        let direct = build(&|m| {
            for i in [1u64, 2, 3, 4] {
                m.insert(&key(i), &(i * 10));
            }
        });
        let via_history = build(&|m| {
            for i in [4u64, 9, 2, 7, 1, 3] {
                m.insert(&key(i), &(i * 10));
            }
            m.insert(&key(9), &999);
            m.remove(&key(9));
            m.remove(&key(7));
        });
        assert_eq!(
            direct, via_history,
            "row layout must not depend on mutation history"
        );
    }

    #[test]
    fn empty_and_single_leaf_trees_have_no_node_rows() {
        fresh();
        let mut m = map();
        let p = m.params();
        assert_eq!(m.root(), *state::empty_chain(&p).last().unwrap());
        assert_eq!(m.len(), 0);

        m.insert(&key(1), &7);
        mock::commit(end_dispatch());
        let rows = mock::snapshot();
        assert!(
            rows.keys().all(|k| !k.starts_with(b"s/committed/n")),
            "a single leaf needs no branch nodes: {rows:?}"
        );
        // Root = the leaf's full spine.
        let chain = state::empty_chain(&p);
        let expected = state::spine_hash(
            &p,
            &chain,
            &key(1),
            leaf_hash(&p, &7u64.encode()),
            0,
            p.depth(),
        );
        let m2 = {
            let mut m2: CommittedMap<[u8; 16], u64> = CommittedMap::default();
            m2.__init(b"s/committed/");
            m2
        };
        assert_eq!(m2.root(), expected);
    }

    #[test]
    fn removing_the_last_entries_returns_to_the_empty_root() {
        fresh();
        let mut m = map();
        let p = m.params();
        for i in 0..8u64 {
            m.insert(&key(i), &i);
        }
        for i in 0..8u64 {
            assert!(m.remove(&key(i)));
        }
        assert_eq!(m.len(), 0);
        assert_eq!(m.root(), *state::empty_chain(&p).last().unwrap());
        mock::commit(end_dispatch());
        let rows = mock::snapshot();
        // Only the root row remains (value rows tombstoned, nodes
        // collapsed away).
        assert!(
            rows.keys()
                .all(|k| k.as_slice() == b"s/committed/r".as_slice()),
            "emptied tree must leave only the root row: {:?}",
            rows.keys().collect::<Vec<_>>()
        );
    }

    #[test]
    fn works_at_narrow_key_widths() {
        fresh();
        let mut m: CommittedMap<u16, u64> = CommittedMap::default();
        m.__init(b"s/narrow/");
        let p = m.params();
        let mut model: BTreeMap<u16, u64> = BTreeMap::new();
        for i in [9u16, 1, 65535, 0, 300, 12] {
            m.insert(&i, &(i as u64));
            model.insert(i, i as u64);
        }
        m.remove(&300);
        model.remove(&300);
        let leaves: Vec<(Vec<u8>, [u8; 32])> = model
            .iter()
            .map(|(k, v)| {
                let mut kb = Vec::new();
                k.write_to(&mut kb);
                (kb, leaf_hash(&p, &v.encode()))
            })
            .collect();
        assert_eq!(m.root(), root_of_sorted(&p, &leaves));
        let keys: Vec<u16> = m.iter().map(|(k, _)| k).collect();
        assert_eq!(keys, model.keys().copied().collect::<Vec<_>>());
    }
}
