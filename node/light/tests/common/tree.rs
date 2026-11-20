//! The reference credential tree and its feed.

use std::collections::BTreeMap;

use vos_abi::credentials::{self, DEPTH, EMPTY, Words, compress};
use vos_abi::{Decode, Encode};
use vos_light::{AuthWitness, Digest};
use vos_wire::credentials::{Change, Feed, RootEntry, method};
use vos_wire::ingress::QueryCall;

/// A sparse tree of depth 32 over `C`, rebuilt from its leaves at every
/// read: the credential actor's, as `proving.md` §8 defines it.
#[derive(Clone, Default)]
pub struct Tree {
    pub leaves: BTreeMap<u32, Words>,
}

impl Tree {
    /// `member`'s leaf at `slot`.
    pub fn enroll(&mut self, slot: u32, member: &Digest) {
        self.set(slot, credentials::leaf(&member.0));
    }

    /// `leaf` at `slot`; the empty leaf clears it.
    pub fn set(&mut self, slot: u32, leaf: Words) {
        if leaf == EMPTY[0] {
            self.leaves.remove(&slot);
        } else {
            self.leaves.insert(slot, leaf);
        }
    }

    fn node(&self, level: usize, index: u64) -> Words {
        let first = index << level;
        let last = (first + (1u64 << level) - 1).min(u64::from(u32::MAX));
        if self
            .leaves
            .range(first as u32..=last as u32)
            .next()
            .is_none()
        {
            return EMPTY[level];
        }
        if level == 0 {
            return self.leaves[&(index as u32)];
        }
        compress(
            &self.node(level - 1, 2 * index),
            &self.node(level - 1, 2 * index + 1),
        )
    }

    pub fn root(&self) -> Digest {
        Digest(self.node(DEPTH, 0))
    }

    pub fn siblings(&self, slot: u32) -> [Digest; DEPTH] {
        core::array::from_fn(|level| Digest(self.node(level, u64::from(slot >> level ^ 1))))
    }

    /// The path of the member at `slot`, at the tree's root.
    pub fn witness(&self, slot: u32) -> AuthWitness {
        AuthWitness {
            root: self.root(),
            slot,
            siblings: self.siblings(slot),
        }
    }
}

/// The feed of a sequence of writes, and the reference after each.
#[derive(Default)]
pub struct Writes {
    pub tree: Tree,
    pub changes: Vec<Change>,
}

impl Writes {
    /// A write at `time` setting `leaves` (an empty leaf revokes).
    pub fn write(&mut self, time: u64, leaves: &[(u32, Words)]) {
        let mut set: Vec<(u32, [u8; 32])> = Vec::new();
        for &(slot, leaf) in leaves {
            self.tree.set(slot, leaf);
            set.push((slot, credentials::digest(&leaf)));
        }
        set.sort_unstable_by_key(|(slot, _)| *slot);
        self.changes.push(Change {
            leaves: set,
            root: RootEntry {
                root: self.tree.root().to_bytes(),
                since: time,
            },
        });
    }

    /// The page of the changes `from..to`.
    pub fn page(&self, from: usize, to: usize) -> Feed {
        Feed {
            from: from as u64,
            changes: self.changes[from..to].to_vec(),
            length: self.changes.len() as u64,
        }
    }
}

/// The credential actor's reply over `changes` to `query`, a query of
/// `feed(from)` or of `feed_after(root)`, at most `per_page` changes a
/// page: none for another method.
pub fn serve_feed(changes: &[Change], query: &QueryCall, per_page: usize) -> Option<Vec<u8>> {
    let length = changes.len();
    let page = |from: usize| Feed {
        from: from as u64,
        changes: changes[from.min(length)..(from.min(length) + per_page).min(length)].to_vec(),
        length: length as u64,
    };
    if query.method == method::FEED {
        let from = u64::decode_exact(&query.arguments).expect("a place");
        Some(page(from as usize).encode())
    } else if query.method == method::FEED_AFTER {
        let root = <[u8; 32]>::decode_exact(&query.arguments).expect("a root");
        let after = changes
            .iter()
            .rposition(|change| change.root.root == root)
            .map(|last| page(last + 1));
        Some(after.encode())
    } else {
        None
    }
}
