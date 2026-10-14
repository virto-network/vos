//! Range proofs: every key in `[from, to)`, shown complete.

use alloc::vec;
use alloc::vec::Vec;

use scale::{Decode, Encode};

use crate::hash::Hasher;
use crate::keys::{Side, bit, side};
use crate::partial::Slot;
use crate::proof::{Entry, Witness};
use crate::store::{Child, NodeStore, load, load_leaf};
use crate::{Error, Hash, valid_key};

/// A proof that the leaves it opens between its boundaries are every key in
/// `[from, to)`. A range with `to` below `from` is the empty `[from, from)`.
///
/// Its boundaries are leaves: the largest key below `from` and the first
/// key at or past `to`, or the tree's edge where there is none. It opens
/// both boundaries' paths, their outer siblings closed, and every subtree
/// between them down to its leaves. A cursor between keys has no leaf, and
/// a subtree beside its path, closed, could not show which side of it lies.
///
/// A bounded scan from a cursor proves the range from the cursor to
/// [`after`](crate::keys::after) its last row, or, when it returned fewer
/// rows than its limit, to the [`prefix_end`](crate::keys::prefix_end) of
/// the scanned prefix.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct RangeProof {
    pub entries: Vec<Entry>,
}

impl RangeProof {
    /// The proof of `[from, to)` in the tree `store` holds; `to` is `None`
    /// for the tree's right edge.
    pub fn generate<S: NodeStore>(
        store: &S,
        from: &[u8],
        to: Option<&[u8]>,
    ) -> Result<Self, S::Error> {
        let Some(top) = store.top()? else {
            return Ok(Self {
                entries: vec![Entry::Empty],
            });
        };
        let to = to.map(|to| to.max(from));
        let low = last_below(store, &top, from)?;
        let high = match to {
            Some(to) => first_from(store, &top, to)?,
            None => None,
        };
        let mut entries = Vec::new();
        let mut stack = vec![top];
        while let Some(child) = stack.pop() {
            let outside = low
                .as_deref()
                .is_some_and(|low| lies(&child, low) == Side::Above)
                || high
                    .as_deref()
                    .is_some_and(|high| lies(&child, high) == Side::Below);
            if outside {
                entries.push(Entry::Hash(*child.hash()));
                continue;
            }
            match child {
                Child::Leaf { key, .. } => {
                    let value_hash = load_leaf(store, &key)?.value_hash;
                    entries.push(Entry::Leaf { key, value_hash });
                }
                Child::Branch { level, prefix, .. } => {
                    let node = load(store, level, &prefix)?;
                    entries.push(Entry::Branch(level));
                    stack.push(node.right);
                    stack.push(node.left);
                }
            }
        }
        Ok(Self { entries })
    }

    /// Check the proof against `root`, and that `rows`, keys and their
    /// values' commitments, are every key in `[from, to)` in order; `to` is
    /// `None` for the tree's right edge. A row with an empty or overlong key
    /// is refused as [`Error::Key`].
    pub fn verify<H: Hasher, K: AsRef<[u8]>>(
        &self,
        hasher: &H,
        root: &Hash,
        from: &[u8],
        to: Option<&[u8]>,
        rows: &[(K, Hash)],
    ) -> Result<Witness, Error> {
        if !rows.iter().all(|(key, _)| valid_key(key.as_ref())) {
            return Err(Error::Key);
        }
        let witness = Witness::open(hasher, &self.entries, root)?;
        let to = to.map(|to| to.max(from));
        // The opened leaves and the closed subtrees, in order: the slots of a
        // freshly opened proof are in pre-order. Opening checked that the
        // leaves are in strictly increasing order.
        let ends: Vec<Option<(&[u8], &Hash)>> = witness
            .tree()
            .slots
            .iter()
            .filter_map(|slot| match slot {
                Slot::Leaf {
                    key,
                    value_hash: Some(value_hash),
                    ..
                } => Some(Some((key.as_slice(), value_hash))),
                Slot::Closed(_) => Some(None),
                _ => None,
            })
            .collect();
        // Before the range, anything, the last of it a leaf: the predecessor.
        let start = ends
            .iter()
            .position(|end| end.is_some_and(|(key, _)| key >= from))
            .unwrap_or(ends.len());
        if start > 0 && ends[start - 1].is_none() {
            return Err(Error::Uncovered);
        }
        // The range, then a leaf at or past `to`, or the tree's right edge.
        let below_to = |key: &[u8]| to.is_none_or(|to| key < to);
        let stop = ends[start..]
            .iter()
            .position(|end| !end.is_some_and(|(key, _)| below_to(key)))
            .map_or(ends.len(), |len| start + len);
        if ends.get(stop).is_some_and(Option::is_none) {
            return Err(Error::Uncovered);
        }
        let shown = &ends[start..stop];
        let matches = shown.len() == rows.len()
            && shown
                .iter()
                .zip(rows)
                .all(|(end, (key, value))| *end == Some((key.as_ref(), value)));
        if !matches {
            return Err(Error::Claim);
        }
        Ok(witness)
    }

    /// The root after `writes` to keys in the range or at its boundaries,
    /// from the proof alone.
    pub fn update<H: Hasher, K: AsRef<[u8]>>(
        &self,
        hasher: &H,
        writes: &[(K, Option<Hash>)],
    ) -> Result<Hash, Error> {
        Witness::unchecked(&self.entries)?.update(hasher, writes)
    }
}

/// Where `bound` lies against the keys of `child`.
fn lies(child: &Child, bound: &[u8]) -> Side {
    match child {
        Child::Leaf { key, .. } => match bound.cmp(key) {
            core::cmp::Ordering::Less => Side::Below,
            core::cmp::Ordering::Equal => Side::Within,
            core::cmp::Ordering::Greater => Side::Above,
        },
        Child::Branch { level, prefix, .. } => side(bound, prefix, *level),
    }
}

/// The largest key below `bound`.
fn last_below<S: NodeStore>(
    store: &S,
    top: &Child,
    bound: &[u8],
) -> Result<Option<Vec<u8>>, S::Error> {
    // The nearest subtree the search passed on its left: all below the bound.
    let mut passed = None;
    let mut at = top.clone();
    loop {
        match (lies(&at, bound), at) {
            (Side::Above, at) => return edge(store, at, 1).map(Some),
            (Side::Within, Child::Branch { level, prefix, .. }) => {
                let node = load(store, level, &prefix)?;
                if bit(bound, level) == 1 {
                    passed = Some(node.left);
                    at = node.right;
                } else {
                    at = node.left;
                }
            }
            _ => break,
        }
    }
    passed.map(|child| edge(store, child, 1)).transpose()
}

/// The first key at or past `bound`.
fn first_from<S: NodeStore>(
    store: &S,
    top: &Child,
    bound: &[u8],
) -> Result<Option<Vec<u8>>, S::Error> {
    // The nearest subtree the search passed on its right: all past the bound.
    let mut passed = None;
    let mut at = top.clone();
    loop {
        match (lies(&at, bound), at) {
            (Side::Below, at) | (Side::Within, at @ Child::Leaf { .. }) => {
                return edge(store, at, 0).map(Some);
            }
            (Side::Within, Child::Branch { level, prefix, .. }) => {
                let node = load(store, level, &prefix)?;
                if bit(bound, level) == 0 {
                    passed = Some(node.right);
                    at = node.left;
                } else {
                    at = node.right;
                }
            }
            (Side::Above, _) => break,
        }
    }
    passed.map(|child| edge(store, child, 0)).transpose()
}

/// The first key of `child`'s subtree (`side` 0), or its last (1).
fn edge<S: NodeStore>(store: &S, mut child: Child, side: usize) -> Result<Vec<u8>, S::Error> {
    loop {
        match child {
            Child::Leaf { key, .. } => return Ok(key),
            Child::Branch { level, prefix, .. } => {
                let node = load(store, level, &prefix)?;
                child = if side == 0 { node.left } else { node.right };
            }
        }
    }
}
