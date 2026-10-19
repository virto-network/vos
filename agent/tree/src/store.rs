//! The tree as rows: the storage the node's root builder keeps it in.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use scale::{Decode, Encode};

use crate::hash::{Hasher, empty_root};
use crate::keys::{bit, prefix_of};
use crate::{Error, Hash, Leaf};

/// A subtree, as its parent's row names it.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub enum Child {
    #[codec(index = 0)]
    Leaf { key: Vec<u8>, hash: Hash },
    /// A branch, by its row's place: its level and the first `level` bits
    /// of its keys, in whole bytes with the bits past `level` zero.
    #[codec(index = 1)]
    Branch {
        level: u16,
        prefix: Vec<u8>,
        hash: Hash,
    },
}

impl Child {
    pub fn hash(&self) -> &Hash {
        match self {
            Child::Leaf { hash, .. } | Child::Branch { hash, .. } => hash,
        }
    }
}

/// A branch's row: its children.
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
pub struct Node {
    pub left: Child,
    pub right: Child,
}

/// Where a tree's rows live: a row per branch, by its level and prefix, a
/// row per leaf, by its key, and the top reference.
///
/// Rows exist only for the tree's branches and leaves: the algorithms walk
/// from the top through the references rows hold, so they need point reads
/// alone. [`update`](crate::update) reads every row it needs before it
/// writes any, so an implementation may read a snapshot and gather the
/// writes into one commit.
///
/// The error carries the tree's own refusals too: a batch with a key that is
/// not prefix-free, or a row a parent names that the store does not hold.
pub trait NodeStore {
    type Error: From<crate::Error>;

    /// The root's reference, `None` for the empty tree.
    fn top(&self) -> Result<Option<Child>, Self::Error>;
    fn node(&self, level: u16, prefix: &[u8]) -> Result<Option<Node>, Self::Error>;
    fn leaf(&self, key: &[u8]) -> Result<Option<Leaf>, Self::Error>;

    fn set_top(&mut self, top: Option<Child>) -> Result<(), Self::Error>;
    fn put_node(&mut self, level: u16, prefix: &[u8], node: Node) -> Result<(), Self::Error>;
    fn delete_node(&mut self, level: u16, prefix: &[u8]) -> Result<(), Self::Error>;
    fn put_leaf(&mut self, key: &[u8], leaf: Leaf) -> Result<(), Self::Error>;
    fn delete_leaf(&mut self, key: &[u8]) -> Result<(), Self::Error>;
}

/// A branch's row, which its parent names: present in a consistent store.
pub(crate) fn load<S: NodeStore>(store: &S, level: u16, prefix: &[u8]) -> Result<Node, S::Error> {
    store.node(level, prefix)?.ok_or(Error::Missing.into())
}

/// A leaf's row, which its parent names.
pub(crate) fn load_leaf<S: NodeStore>(store: &S, key: &[u8]) -> Result<Leaf, S::Error> {
    store.leaf(key)?.ok_or(Error::Missing.into())
}

/// The root of the tree `store` holds.
pub fn stored_root<S: NodeStore, H: Hasher>(hasher: &H, store: &S) -> Result<Hash, S::Error> {
    Ok(store
        .top()?
        .map_or_else(|| empty_root(hasher), |top| *top.hash()))
}

/// The node of the tree in `store` at the byte prefix `prefix`: the root of
/// the subtree over exactly the keys that start with it, `None` when no key
/// does. A branch's level is the first bit at which its keys differ, so the
/// keys sharing a prefix are the leaves of one node, whose hash is the root
/// of the tree over those keys alone.
pub fn node_at<S: NodeStore>(store: &S, prefix: &[u8]) -> Result<Option<Child>, S::Error> {
    let bits = prefix.len() * 8;
    let mut next = store.top()?;
    while let Some(child) = next {
        let (level, place) = match &child {
            Child::Leaf { key, .. } => return Ok(key.starts_with(prefix).then_some(child)),
            Child::Branch { level, prefix, .. } => (*level, prefix),
        };
        // The branch's keys share their first `level` bits, `place`.
        let shared = usize::from(level).min(bits) as u16;
        if prefix_of(place, shared) != prefix_of(prefix, shared) {
            return Ok(None);
        }
        if usize::from(level) >= bits {
            return Ok(Some(child));
        }
        let node = load(store, level, place)?;
        next = Some(match bit(prefix, level) {
            0 => node.left,
            _ => node.right,
        });
    }
    Ok(None)
}

/// The rows the tree in a store reaches from its top.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rows {
    /// Branches' places, in walk order.
    pub nodes: Vec<(u16, Vec<u8>)>,
    /// Leaves' keys, in key order.
    pub leaves: Vec<Vec<u8>>,
}

/// The rows reachable from `store`'s top. A consistent store holds these and
/// no others.
pub fn reachable<S: NodeStore>(store: &S) -> Result<Rows, S::Error> {
    let mut rows = Rows::default();
    let mut stack: Vec<Child> = store.top()?.into_iter().collect();
    while let Some(child) = stack.pop() {
        match child {
            Child::Leaf { key, .. } => rows.leaves.push(key),
            Child::Branch { level, prefix, .. } => {
                let node = load(store, level, &prefix)?;
                rows.nodes.push((level, prefix));
                stack.push(node.right);
                stack.push(node.left);
            }
        }
    }
    Ok(rows)
}

/// A store in memory.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct MemStore {
    pub top: Option<Child>,
    pub nodes: BTreeMap<(u16, Vec<u8>), Node>,
    pub leaves: BTreeMap<Vec<u8>, Leaf>,
}

impl NodeStore for MemStore {
    type Error = crate::Error;

    fn top(&self) -> Result<Option<Child>, Error> {
        Ok(self.top.clone())
    }

    fn node(&self, level: u16, prefix: &[u8]) -> Result<Option<Node>, Error> {
        Ok(self.nodes.get(&(level, prefix.to_vec())).cloned())
    }

    fn leaf(&self, key: &[u8]) -> Result<Option<Leaf>, Error> {
        Ok(self.leaves.get(key).copied())
    }

    fn set_top(&mut self, top: Option<Child>) -> Result<(), Error> {
        self.top = top;
        Ok(())
    }

    fn put_node(&mut self, level: u16, prefix: &[u8], node: Node) -> Result<(), Error> {
        self.nodes.insert((level, prefix.to_vec()), node);
        Ok(())
    }

    fn delete_node(&mut self, level: u16, prefix: &[u8]) -> Result<(), Error> {
        self.nodes.remove(&(level, prefix.to_vec()));
        Ok(())
    }

    fn put_leaf(&mut self, key: &[u8], leaf: Leaf) -> Result<(), Error> {
        self.leaves.insert(key.to_vec(), leaf);
        Ok(())
    }

    fn delete_leaf(&mut self, key: &[u8]) -> Result<(), Error> {
        self.leaves.remove(key);
        Ok(())
    }
}
