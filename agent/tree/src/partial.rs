//! A tree in part: the nodes some keys' paths reach, every other subtree
//! closed under its hash. A proof opens into one, and an update of a store
//! loads one; writes apply to it alike.

use alloc::vec;
use alloc::vec::Vec;

use crate::hash::{Hasher, branch_hash, empty_root, leaf_hash};
use crate::keys::{bit, first_difference, prefix_of};
use crate::store::{Child, Node, NodeStore, load};
use crate::{Error, Hash};

pub(crate) enum Slot {
    /// The empty tree, only ever the root.
    Empty,
    /// A subtree a proof gives by its hash.
    Closed(Hash),
    /// A stored branch not loaded.
    Stored {
        level: u16,
        prefix: Vec<u8>,
        hash: Hash,
    },
    /// A leaf: its key, and its value's commitment when known. A leaf
    /// loaded from a store is known by its hash alone.
    Leaf {
        key: Vec<u8>,
        value_hash: Option<Hash>,
        hash: Option<Hash>,
    },
    Branch(Branch),
}

pub(crate) struct Branch {
    pub level: u16,
    pub children: [u32; 2],
    /// `None` once a write below it changed it.
    pub hash: Option<Hash>,
    /// Its row's place, in a store's tree.
    pub prefix: Vec<u8>,
    /// Whether a store holds its row.
    pub stored: bool,
}

/// A branch on a key's path, and the side the path takes there.
type Step = (u32, usize);

enum Place {
    Empty,
    Found {
        path: Vec<Step>,
        leaf: u32,
    },
    /// The key is absent. Its leaf goes into a new branch at `level`, beside
    /// `below`, at the end of `path`.
    Absent {
        path: Vec<Step>,
        below: u32,
        level: u16,
    },
}

pub(crate) struct Partial {
    pub slots: Vec<Slot>,
    pub root: u32,
    /// The places of the stored branches writes took off the tree.
    pub removed: Vec<(u16, Vec<u8>)>,
}

impl Partial {
    pub(crate) fn new(slots: Vec<Slot>) -> Self {
        Self {
            slots,
            root: 0,
            removed: Vec::new(),
        }
    }

    /// A store's tree, nothing loaded below its top.
    pub(crate) fn from_top(top: Option<Child>) -> Self {
        Self::new(vec![top.map_or(Slot::Empty, unloaded)])
    }

    pub(crate) fn slot(&self, at: u32) -> &Slot {
        &self.slots[at as usize]
    }

    fn branch(&self, at: u32) -> &Branch {
        match self.slot(at) {
            Slot::Branch(branch) => branch,
            _ => unreachable!("a branch"),
        }
    }

    fn branch_mut(&mut self, at: u32) -> &mut Branch {
        match &mut self.slots[at as usize] {
            Slot::Branch(branch) => branch,
            _ => unreachable!("a branch"),
        }
    }

    fn push(&mut self, slot: Slot) -> u32 {
        self.slots.push(slot);
        (self.slots.len() - 1) as u32
    }

    /// The node `key`'s path ends at.
    pub(crate) fn end(&self, key: &[u8]) -> u32 {
        let mut at = self.root;
        while let Slot::Branch(branch) = self.slot(at) {
            at = branch.children[bit(key, branch.level)];
        }
        at
    }

    /// Load `key`'s path from `store`, down to its end.
    pub(crate) fn reach<S: NodeStore>(&mut self, store: &S, key: &[u8]) -> Result<(), S::Error> {
        let mut at = self.root;
        loop {
            match self.slot(at) {
                Slot::Branch(branch) => at = branch.children[bit(key, branch.level)],
                Slot::Stored { level, prefix, .. } => {
                    let node = load(store, *level, prefix)?;
                    let Slot::Stored {
                        level,
                        prefix,
                        hash,
                    } = core::mem::replace(&mut self.slots[at as usize], Slot::Empty)
                    else {
                        unreachable!()
                    };
                    let left = self.push(unloaded(node.left));
                    let right = self.push(unloaded(node.right));
                    self.slots[at as usize] = Slot::Branch(Branch {
                        level,
                        children: [left, right],
                        hash: Some(hash),
                        prefix,
                        stored: true,
                    });
                }
                _ => return Ok(()),
            }
        }
    }

    /// Where `key` is, or would go.
    fn locate(&self, key: &[u8]) -> Result<Place, Error> {
        let mut path = Vec::new();
        let mut at = self.root;
        loop {
            match self.slot(at) {
                Slot::Empty => return Ok(Place::Empty),
                Slot::Branch(branch) => {
                    let side = bit(key, branch.level);
                    path.push((at, side));
                    at = branch.children[side];
                }
                Slot::Leaf { key: other, .. } => {
                    if other.as_slice() == key {
                        return Ok(Place::Found { path, leaf: at });
                    }
                    // The leaf a path reaches shares the longest prefix with
                    // the key, so the key parts from the tree where it parts
                    // from this leaf.
                    let level = first_difference(key, other).ok_or(Error::Key)?;
                    return self.absent(path, at, level);
                }
                Slot::Closed(_) | Slot::Stored { .. } => {
                    // The path leaves what is open. The key is absent, with
                    // its place found, if it parts from the keys below the
                    // last branch it took above that branch's level: every
                    // key below shares those bits.
                    let &(last, _) = path.last().ok_or(Error::Uncovered)?;
                    let leaf = self.any_leaf(last).ok_or(Error::Uncovered)?;
                    let Slot::Leaf { key: other, .. } = self.slot(leaf) else {
                        unreachable!()
                    };
                    let level = first_difference(key, other).ok_or(Error::Key)?;
                    if level >= self.branch(last).level {
                        return Err(Error::Uncovered);
                    }
                    return self.absent(path, at, level);
                }
            }
        }
    }

    /// An absent key that parts from the tree at `level`, on a path that
    /// ended at `end`: its branch goes above the first node of the path
    /// deeper than `level`.
    fn absent(&self, mut path: Vec<Step>, end: u32, level: u16) -> Result<Place, Error> {
        let at = path
            .iter()
            .position(|&(branch, _)| self.branch(branch).level >= level)
            .unwrap_or(path.len());
        let below = match path.get(at) {
            Some(&(branch, _)) if self.branch(branch).level == level => {
                return Err(Error::Malformed);
            }
            Some(&(branch, _)) => branch,
            None => end,
        };
        path.truncate(at);
        Ok(Place::Absent { path, below, level })
    }

    /// A leaf the tree opens below `at`.
    fn any_leaf(&self, at: u32) -> Option<u32> {
        let mut stack = vec![at];
        while let Some(at) = stack.pop() {
            match self.slot(at) {
                Slot::Leaf { .. } => return Some(at),
                Slot::Branch(branch) => stack.extend(branch.children),
                _ => {}
            }
        }
        None
    }

    /// Apply `writes`, in strictly increasing key order, of a value's
    /// commitment to put at a key or `None` to delete it. The puts go first,
    /// then the deletes, all found before any is removed: a removal lifts a
    /// closed sibling into a path, where a later write could need what it
    /// hides. Returns the indices of the writes that deleted a present key.
    pub(crate) fn apply<K: AsRef<[u8]>>(
        &mut self,
        writes: &[(K, Option<Hash>)],
    ) -> Result<Vec<usize>, Error> {
        for (key, value_hash) in writes {
            let (key, Some(value_hash)) = (key.as_ref(), value_hash) else {
                continue;
            };
            let slot = Slot::Leaf {
                key: key.to_vec(),
                value_hash: Some(*value_hash),
                hash: None,
            };
            match self.locate(key)? {
                Place::Empty => self.root = self.push(slot),
                Place::Found { path, leaf } => {
                    self.slots[leaf as usize] = slot;
                    self.invalidate(&path);
                }
                Place::Absent { path, below, level } => {
                    let new = self.push(slot);
                    let mut children = [below; 2];
                    children[bit(key, level)] = new;
                    let branch = self.push(Slot::Branch(Branch {
                        level,
                        children,
                        hash: None,
                        prefix: prefix_of(key, level),
                        stored: false,
                    }));
                    self.link(&path, branch);
                    self.invalidate(&path);
                }
            }
        }
        let mut deleted = Vec::new();
        for (index, (key, value_hash)) in writes.iter().enumerate() {
            if value_hash.is_none() && matches!(self.locate(key.as_ref())?, Place::Found { .. }) {
                deleted.push(index);
            }
        }
        for &index in &deleted {
            let Place::Found { mut path, .. } = self.locate(writes[index].0.as_ref())? else {
                unreachable!("a key found present")
            };
            let Some((parent, side)) = path.pop() else {
                self.root = self.push(Slot::Empty);
                continue;
            };
            let branch = self.branch(parent);
            let sibling = branch.children[1 - side];
            if branch.stored {
                let place = (branch.level, branch.prefix.clone());
                self.removed.push(place);
            }
            self.link(&path, sibling);
            self.invalidate(&path);
        }
        Ok(deleted)
    }

    /// Make `node` the child the last step of `path` takes, or the root.
    fn link(&mut self, path: &[Step], node: u32) {
        match path.last() {
            Some(&(branch, side)) => self.branch_mut(branch).children[side] = node,
            None => self.root = node,
        }
    }

    fn invalidate(&mut self, path: &[Step]) {
        for &(branch, _) in path {
            self.branch_mut(branch).hash = None;
        }
    }

    /// Hash every node a write changed, collecting the branches hashed into
    /// `rehashed`, and return the root.
    pub(crate) fn rehash<H: Hasher>(
        &mut self,
        hasher: &H,
        mut rehashed: Option<&mut Vec<u32>>,
    ) -> Hash {
        let mut stack = vec![(self.root, false)];
        while let Some((at, ready)) = stack.pop() {
            match &mut self.slots[at as usize] {
                Slot::Leaf {
                    key,
                    value_hash,
                    hash: hash @ None,
                } => {
                    let value_hash = value_hash.as_ref().expect("a leaf written or opened");
                    *hash = Some(leaf_hash(hasher, key, value_hash));
                }
                Slot::Branch(Branch {
                    level,
                    children,
                    hash: None,
                    ..
                }) => {
                    let (level, children) = (*level, *children);
                    if ready {
                        let left = self.hash(children[0]);
                        let right = self.hash(children[1]);
                        self.branch_mut(at).hash = Some(branch_hash(hasher, level, &left, &right));
                        if let Some(rehashed) = rehashed.as_deref_mut() {
                            rehashed.push(at);
                        }
                    } else {
                        stack.push((at, true));
                        stack.extend(children.map(|child| (child, false)));
                    }
                }
                _ => {}
            }
        }
        match self.slot(self.root) {
            Slot::Empty => empty_root(hasher),
            _ => self.hash(self.root),
        }
    }

    /// A hashed node's hash.
    fn hash(&self, at: u32) -> Hash {
        match self.slot(at) {
            Slot::Closed(hash) | Slot::Stored { hash, .. } => *hash,
            Slot::Leaf {
                hash: Some(hash), ..
            }
            | Slot::Branch(Branch {
                hash: Some(hash), ..
            }) => *hash,
            _ => unreachable!("a hashed node"),
        }
    }

    /// A hashed node of a store's tree, as its parent's row names it.
    fn child(&self, at: u32) -> Child {
        let hash = self.hash(at);
        match self.slot(at) {
            Slot::Leaf { key, .. } => Child::Leaf {
                key: key.clone(),
                hash,
            },
            Slot::Branch(Branch { level, prefix, .. }) | Slot::Stored { level, prefix, .. } => {
                Child::Branch {
                    level: *level,
                    prefix: prefix.clone(),
                    hash,
                }
            }
            _ => unreachable!("a node of a store's tree"),
        }
    }

    /// A hashed branch's row: its place and its children.
    pub(crate) fn row(&self, at: u32) -> (u16, &[u8], Node) {
        let branch = self.branch(at);
        let node = Node {
            left: self.child(branch.children[0]),
            right: self.child(branch.children[1]),
        };
        (branch.level, &branch.prefix, node)
    }

    /// The hashed root's reference, `None` for the empty tree.
    pub(crate) fn top(&self) -> Option<Child> {
        match self.slot(self.root) {
            Slot::Empty => None,
            _ => Some(self.child(self.root)),
        }
    }
}

/// The slot of a stored node not loaded: a leaf, known by its hash, or a
/// branch.
fn unloaded(child: Child) -> Slot {
    match child {
        Child::Leaf { key, hash } => Slot::Leaf {
            key,
            value_hash: None,
            hash: Some(hash),
        },
        Child::Branch {
            level,
            prefix,
            hash,
        } => Slot::Stored {
            level,
            prefix,
            hash,
        },
    }
}
