//! Proofs as pruned trees, and the multiproof of a set of keys.

use alloc::vec;
use alloc::vec::Vec;

use scale::{Decode, Encode};

use crate::hash::Hasher;
use crate::keys::{bit, first_difference};
use crate::partial::{Branch, Partial, Slot};
use crate::store::{Child, NodeStore, load, load_leaf};
use crate::{Error, Hash, valid_key};

/// A node of a pruned tree, in pre-order.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Entry {
    /// A branch at this level: its left subtree follows, then its right.
    #[codec(index = 0)]
    Branch(u16),
    /// A subtree left closed, by its hash.
    #[codec(index = 1)]
    Hash(Hash),
    /// A leaf, opened: its key and its value's commitment.
    #[codec(index = 2)]
    Leaf { key: Vec<u8>, value_hash: Hash },
    /// The empty tree, the only entry.
    #[codec(index = 3)]
    Empty,
}

/// A multiproof of a set of keys: each key's path, ending at its own leaf,
/// at the leaf that shows it absent, or at the empty tree.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct BatchProof {
    pub entries: Vec<Entry>,
}

/// A proof's tree, opened and checked against a root. Updates rehash only
/// the paths they change.
pub struct PartialTree {
    tree: Partial,
}

impl BatchProof {
    /// The proof of `keys` in the tree `store` holds.
    pub fn generate<S: NodeStore, K: AsRef<[u8]>>(store: &S, keys: &[K]) -> Result<Self, S::Error> {
        let Some(top) = store.top()? else {
            return Ok(Self {
                entries: vec![Entry::Empty],
            });
        };
        let mut entries = Vec::new();
        let mut stack: Vec<(Child, Vec<&[u8]>)> =
            vec![(top, keys.iter().map(AsRef::as_ref).collect())];
        while let Some((child, keys)) = stack.pop() {
            if keys.is_empty() {
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
                    let (right, left) = keys.into_iter().partition(|key| bit(key, level) == 1);
                    stack.push((node.right, right));
                    stack.push((node.left, left));
                }
            }
        }
        Ok(Self { entries })
    }

    /// Check the proof against `root` and each claim: a key and its value's
    /// commitment if present, or `None` if absent.
    ///
    /// A claim about a key that is empty, too long, or a prefix of a key of
    /// the tree or prefixed by one is refused as [`Error::Key`]: the tree's
    /// keys are prefix-free, so such a key could never be put in it, and a
    /// key this accepts as absent can always be put from the proof.
    pub fn verify<H: Hasher, K: AsRef<[u8]>>(
        &self,
        hasher: &H,
        root: &Hash,
        claims: &[(K, Option<Hash>)],
    ) -> Result<PartialTree, Error> {
        let opened = PartialTree::open(hasher, &self.entries, root)?;
        let tree = &opened.tree;
        for (key, value) in claims {
            let key = key.as_ref();
            if !valid_key(key) {
                return Err(Error::Key);
            }
            let shown = match tree.slot(tree.end(key)) {
                Slot::Empty => None,
                Slot::Leaf {
                    key: other,
                    value_hash: Some(value_hash),
                    ..
                } => {
                    if other.as_slice() == key {
                        Some(*value_hash)
                    } else if first_difference(key, other).is_none() {
                        // The leaf a path reaches shares the longest prefix
                        // with the key: if any key of the tree prefixes this
                        // one or is prefixed by it, this one does.
                        return Err(Error::Key);
                    } else {
                        None
                    }
                }
                _ => return Err(Error::Uncovered),
            };
            if shown != *value {
                return Err(Error::Claim);
            }
        }
        Ok(opened)
    }

    /// The root after `writes` to the proven keys, from the proof alone.
    pub fn update<H: Hasher, K: AsRef<[u8]>>(
        &self,
        hasher: &H,
        writes: &[(K, Option<Hash>)],
    ) -> Result<Hash, Error> {
        PartialTree::unchecked(&self.entries)?.update(hasher, writes)
    }
}

impl PartialTree {
    /// Open `entries` and check them against `root`.
    pub(crate) fn open<H: Hasher>(
        hasher: &H,
        entries: &[Entry],
        root: &Hash,
    ) -> Result<Self, Error> {
        let mut opened = Self::unchecked(entries)?;
        if opened.tree.rehash(hasher, None) != *root {
            return Err(Error::Root);
        }
        Ok(opened)
    }

    /// Open `entries` as a pruned tree of the format, unhashed.
    pub(crate) fn unchecked(entries: &[Entry]) -> Result<Self, Error> {
        if let [Entry::Empty] = entries {
            return Ok(Self {
                tree: Partial::new(vec![Slot::Empty]),
            });
        }
        let mut slots: Vec<Slot> = Vec::with_capacity(entries.len());
        // The branches still missing children, each with the side of the
        // child being read: the path to the next entry.
        let mut open: Vec<(u32, usize)> = Vec::new();
        let mut last: Option<&[u8]> = None;
        let level_of = |slots: &[Slot], at: u32| match &slots[at as usize] {
            Slot::Branch(branch) => branch.level,
            _ => unreachable!("a branch"),
        };
        for entry in entries {
            if !slots.is_empty() && open.is_empty() {
                return Err(Error::Malformed);
            }
            let slot = match entry {
                Entry::Empty => return Err(Error::Malformed),
                Entry::Hash(hash) => Slot::Closed(*hash),
                Entry::Branch(level) => {
                    if open
                        .last()
                        .is_some_and(|&(parent, _)| *level <= level_of(&slots, parent))
                    {
                        return Err(Error::Malformed);
                    }
                    Slot::Branch(Branch {
                        level: *level,
                        children: [0; 2],
                        hash: None,
                        prefix: Vec::new(),
                        stored: false,
                    })
                }
                Entry::Leaf { key, value_hash } => {
                    let placed = open.iter().all(|&(branch, side)| {
                        let level = level_of(&slots, branch);
                        usize::from(level) < key.len() * 8 && bit(key, level) == side
                    });
                    if !valid_key(key) || !placed || last.is_some_and(|last| last >= key) {
                        return Err(Error::Malformed);
                    }
                    last = Some(key);
                    Slot::Leaf {
                        key: key.clone(),
                        value_hash: Some(*value_hash),
                        hash: None,
                    }
                }
            };
            let at = slots.len() as u32;
            let branch = matches!(slot, Slot::Branch(_));
            slots.push(slot);
            if let Some(&(parent, side)) = open.last() {
                let Slot::Branch(parent) = &mut slots[parent as usize] else {
                    unreachable!()
                };
                parent.children[side] = at;
            }
            if branch {
                open.push((at, 0));
                continue;
            }
            // A leaf or a closed subtree completes its parent's child, and
            // perhaps the parent, and so on up.
            while let Some((done, side)) = open.last_mut() {
                *side += 1;
                if *side < 2 {
                    break;
                }
                let Slot::Branch(done) = &slots[*done as usize] else {
                    unreachable!()
                };
                // A canonical proof closes a branch it does not open.
                let closed = |at: u32| matches!(slots[at as usize], Slot::Closed(_));
                if done.children.iter().all(|&child| closed(child)) {
                    return Err(Error::Malformed);
                }
                open.pop();
            }
        }
        if slots.is_empty() || !open.is_empty() {
            return Err(Error::Malformed);
        }
        Ok(Self {
            tree: Partial::new(slots),
        })
    }

    pub(crate) fn tree(&self) -> &Partial {
        &self.tree
    }

    /// Apply `writes` to the proven keys, in strictly increasing key order: a
    /// value's commitment to put at a key, or `None` to delete it. Returns
    /// the new root.
    ///
    /// A put of an absent key needs the leaf its path reaches, or, in a
    /// range proof, the leaves around it. A delete lifts its leaf's sibling,
    /// perhaps closed, into its place, so a later update may find what it
    /// needs closed. On an error the tree is left part-way and unusable.
    pub fn update<H: Hasher, K: AsRef<[u8]>>(
        &mut self,
        hasher: &H,
        writes: &[(K, Option<Hash>)],
    ) -> Result<Hash, Error> {
        if !writes.windows(2).all(|w| w[0].0.as_ref() < w[1].0.as_ref()) {
            return Err(Error::Order);
        }
        if !writes.iter().all(|(key, _)| valid_key(key.as_ref())) {
            return Err(Error::Key);
        }
        self.tree.apply(writes)?;
        Ok(self.tree.rehash(hasher, None))
    }
}

/// The tag of an [`Entry`]'s encoding, its variant's `codec(index)`, which
/// the encoded proof's reader matches on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum EntryTag {
    Branch = 0,
    Hash = 1,
    Leaf = 2,
    Empty = 3,
}

impl EntryTag {
    /// The tag `byte` is; none for another byte.
    pub(crate) const fn of(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::Branch,
            1 => Self::Hash,
            2 => Self::Leaf,
            3 => Self::Empty,
            _ => return None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_tags_are_the_codec_indices() {
        let entries = [
            (Entry::Branch(7), EntryTag::Branch),
            (Entry::Hash([1; 32]), EntryTag::Hash),
            (
                Entry::Leaf {
                    key: vec![2],
                    value_hash: [3; 32],
                },
                EntryTag::Leaf,
            ),
            (Entry::Empty, EntryTag::Empty),
        ];
        for (entry, tag) in entries {
            assert_eq!(entry.encode()[0], tag as u8, "{entry:?}");
            assert_eq!(EntryTag::of(tag as u8), Some(tag));
        }
        assert_eq!(EntryTag::of(4), None);
    }
}
