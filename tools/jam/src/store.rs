//! An agent's whole keyspace on disk: its rows as stored, and one tree over
//! them, each row a leaf salted by the seed of the work result that last
//! wrote it; and where each page its workflows hold was exported.
//!
//! Reads go through a [`View`], one consistent snapshot. A package in
//! flight is a [`Pending`]: its rows and the tree's rows it rewrites, over
//! the view it was built on, with the root they make. Committing it is one
//! atomic batch, and dropping it costs nothing: a package costs what it
//! touches, never the whole state.

use std::collections::{BTreeMap, BTreeSet};
use std::ops::Bound;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};

use fjall::{Database, Keyspace, KeyspaceCreateOptions, Readable, Snapshot};
use vos_tree::{Blake2b, Child, Hash, Leaf, Node, NodeStore, stored_root, update};
use vos_wire::apply::{Host, State, apply};
use vos_wire::ids::WorkflowId;
use vos_wire::records::leaf_value;
use vos_wire::result::WorkResult;
use vos_wire::{Decode, Encode};

use crate::Error;

/// Rows a work result writes: a value as stored, or (`None`) a deletion.
pub type Writes = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

/// Rows as a store reads them, in key order.
pub(crate) type RowsFrom = Box<dyn Iterator<Item = Result<(Vec<u8>, Vec<u8>), Error>>>;

/// Where a page was exported: its package's segment root, and its index
/// among the package's exports.
pub type Exported = (Hash, u32);

/// The tree's rows, each kind under its own first byte.
#[derive(Clone, Copy)]
#[repr(u8)]
enum TreeRow {
    Top = 0,
    Node = 1,
    Leaf = 2,
}

fn node_key(level: u16, prefix: &[u8]) -> Vec<u8> {
    [&[TreeRow::Node as u8][..], &level.to_be_bytes(), prefix].concat()
}

fn leaf_key(key: &[u8]) -> Vec<u8> {
    [&[TreeRow::Leaf as u8][..], key].concat()
}

fn page_key(workflow: WorkflowId, index: u32) -> Vec<u8> {
    [&workflow.0.to_be_bytes()[..], &index.to_be_bytes()].concat()
}

/// An agent's store.
pub struct Store {
    db: Database,
    rows: Keyspace,
    tree: Keyspace,
    pages: Keyspace,
}

impl Store {
    /// The store at `path`, made there if new.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, Error> {
        Self::opened(Database::builder(path.as_ref()).open()?)
    }

    /// A store in a directory of its own under the system's, removed when
    /// it is dropped.
    pub fn temporary() -> Result<Self, Error> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = std::env::temp_dir().join(format!(
            "vos-jam-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        Self::opened(Database::builder(path).temporary(true).open()?)
    }

    fn opened(db: Database) -> Result<Self, Error> {
        Ok(Self {
            rows: db.keyspace("rows", KeyspaceCreateOptions::default)?,
            tree: db.keyspace("tree", KeyspaceCreateOptions::default)?,
            pages: db.keyspace("pages", KeyspaceCreateOptions::default)?,
            db,
        })
    }

    /// The store as it stands, for reading.
    pub fn view(&self) -> View {
        View {
            snapshot: self.db.snapshot(),
            rows: self.rows.clone(),
            tree: self.tree.clone(),
            pages: self.pages.clone(),
        }
    }

    /// The root over the whole keyspace.
    pub fn root(&self) -> Result<Hash, Error> {
        self.view().root()
    }

    /// Write `writes`, made by a work result with `seed`, as a package's
    /// do: the rows, their leaves, and the root after, which it returns.
    /// For tests that hold the tree against a VOS node's.
    #[doc(hidden)]
    pub fn write(&self, writes: Writes, seed: &[u8; 32]) -> Result<Hash, Error> {
        let pending = self.view().stage(writes, seed)?;
        let root = pending.root;
        self.commit(pending)?;
        Ok(root)
    }

    /// Commit `pending`, durably, in one batch: refused, `Error::Root`,
    /// unless the store still holds the root it was staged on.
    pub(crate) fn commit(&self, pending: Pending) -> Result<(), Error> {
        if self.root()? != pending.base {
            return Err(Error::Root);
        }
        let mut batch = self.db.batch();
        let mut write = |keyspace: &Keyspace, key: Vec<u8>, value: Option<Vec<u8>>| match value {
            Some(value) => batch.insert(keyspace, key, value),
            None => batch.remove(keyspace, key),
        };
        for (key, value) in pending.rows {
            write(&self.rows, key, value);
        }
        for (key, value) in pending.tree {
            write(&self.tree, key, value);
        }
        write(
            &self.tree,
            vec![TreeRow::Top as u8],
            Some(pending.top.encode()),
        );
        for ((workflow, index), exported) in pending.pages {
            let exported = exported.map(|exported| exported.encode());
            write(&self.pages, page_key(workflow, index), exported);
        }
        batch
            .durability(Some(fjall::PersistMode::SyncAll))
            .commit()?;
        Ok(())
    }
}

/// The store at one moment.
#[derive(Clone)]
pub struct View {
    snapshot: Snapshot,
    rows: Keyspace,
    tree: Keyspace,
    pages: Keyspace,
}

impl View {
    /// A row as stored.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Ok(self
            .snapshot
            .get(&self.rows, key)?
            .map(|value| value.to_vec()))
    }

    /// The rows from `from` on, in key order.
    pub(crate) fn rows_from(&self, from: &[u8]) -> RowsFrom {
        let bounds = (Bound::Included(from.to_vec()), Bound::Unbounded);
        Box::new(self.snapshot.range(&self.rows, bounds).map(|guard| {
            let (key, value) = guard.into_inner()?;
            Ok((key.to_vec(), value.to_vec()))
        }))
    }

    /// Every row: for tests and comparisons.
    pub fn rows(&self) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Error> {
        self.rows_from(&[]).collect()
    }

    /// A row's leaf: its salt and its value's commitment.
    pub(crate) fn leaf(&self, key: &[u8]) -> Result<Option<Leaf>, Error> {
        self.tree().leaf(key)
    }

    /// The tree as it stands, with nothing written: for proofs.
    pub fn tree(&self) -> Staged<'_> {
        Staged {
            view: self,
            rows: BTreeMap::new(),
            top: None,
        }
    }

    pub fn root(&self) -> Result<Hash, Error> {
        stored_root(&Blake2b, &self.tree())
    }

    /// Where workflow `workflow`'s page `index` was exported.
    pub(crate) fn page(&self, workflow: WorkflowId, index: u32) -> Result<Option<Exported>, Error> {
        let Some(bytes) = self.snapshot.get(&self.pages, page_key(workflow, index))? else {
            return Ok(None);
        };
        Exported::decode_exact(&bytes)
            .map(Some)
            .ok_or(Error::Corrupt("a page's place"))
    }

    /// The rows applying `result` writes, each row it reads put in
    /// `reads`; `None` when it does not apply.
    pub(crate) fn writes(
        &self,
        result: &WorkResult,
        reads: &mut BTreeSet<Vec<u8>>,
    ) -> Result<Option<Writes>, Error> {
        let mut applying = Applying {
            view: self,
            reads,
            writes: Writes::new(),
            error: None,
        };
        let applied = apply(&mut applying, result, Host::Jam);
        if let Some(error) = applying.error {
            return Err(error);
        }
        Ok(applied.then_some(applying.writes))
    }

    /// `writes`, made by a work result with `seed`, staged over this view:
    /// the rows, their leaves, each salted by it, and the root after. A
    /// committed row's leaf commits its bare value, as a VOS node's
    /// ([`leaf_value`]).
    pub(crate) fn stage(&self, writes: Writes, seed: &[u8; 32]) -> Result<Pending, Error> {
        let leaves: Vec<(&[u8], Option<Leaf>)> = writes
            .iter()
            .map(|(key, value)| {
                let leaf = match value {
                    Some(value) => {
                        let value = leaf_value(key, value).ok_or(Error::Corrupt("a value row"))?;
                        Some(Leaf::salted(&Blake2b, seed, key, value))
                    }
                    None => None,
                };
                Ok((key.as_slice(), leaf))
            })
            .collect::<Result<_, Error>>()?;
        let base = self.root()?;
        let mut tree = self.tree();
        let root = update(&Blake2b, &mut tree, &leaves)?;
        let top = tree.top()?;
        let rows = tree.rows;
        Ok(Pending {
            rows: writes,
            tree: rows,
            top,
            base,
            root,
            pages: BTreeMap::new(),
        })
    }
}

/// A package's changes, staged: its rows, the tree's rows they rewrite and
/// its top, the root they were staged on and the root they make, and where
/// its pages were exported.
#[derive(Clone, Debug)]
pub struct Pending {
    rows: Writes,
    tree: Writes,
    top: Option<Child>,
    pub base: Hash,
    pub root: Hash,
    pages: BTreeMap<(WorkflowId, u32), Option<Exported>>,
}

impl Pending {
    /// Record where workflow `workflow`'s page `index` was exported, or,
    /// with `None`, that it is no longer held.
    pub fn page(&mut self, workflow: WorkflowId, index: u32, exported: Option<Exported>) {
        self.pages.insert((workflow, index), exported);
    }
}

/// The tree over a view, with the rows a write gathers above it.
pub struct Staged<'a> {
    view: &'a View,
    rows: Writes,
    /// The top once written; `None` while it is the view's.
    top: Option<Option<Child>>,
}

impl Staged<'_> {
    fn row<T: Decode>(&self, key: &[u8], what: &'static str) -> Result<Option<T>, Error> {
        let bytes = match self.rows.get(key) {
            Some(value) => value.clone(),
            None => self
                .view
                .snapshot
                .get(&self.view.tree, key)?
                .map(|value| value.to_vec()),
        };
        bytes
            .map(|bytes| T::decode_exact(&bytes).ok_or(Error::Corrupt(what)))
            .transpose()
    }
}

impl NodeStore for Staged<'_> {
    type Error = Error;

    fn top(&self) -> Result<Option<Child>, Error> {
        match &self.top {
            Some(top) => Ok(top.clone()),
            None => Ok(self
                .row::<Option<Child>>(&[TreeRow::Top as u8], "the tree's top")?
                .flatten()),
        }
    }

    fn node(&self, level: u16, prefix: &[u8]) -> Result<Option<Node>, Error> {
        self.row(&node_key(level, prefix), "a branch row")
    }

    fn leaf(&self, key: &[u8]) -> Result<Option<Leaf>, Error> {
        self.row(&leaf_key(key), "a leaf row")
    }

    fn set_top(&mut self, top: Option<Child>) -> Result<(), Error> {
        self.top = Some(top);
        Ok(())
    }

    fn put_node(&mut self, level: u16, prefix: &[u8], node: Node) -> Result<(), Error> {
        self.rows
            .insert(node_key(level, prefix), Some(node.encode()));
        Ok(())
    }

    fn delete_node(&mut self, level: u16, prefix: &[u8]) -> Result<(), Error> {
        self.rows.insert(node_key(level, prefix), None);
        Ok(())
    }

    fn put_leaf(&mut self, key: &[u8], leaf: Leaf) -> Result<(), Error> {
        self.rows.insert(leaf_key(key), Some(leaf.encode()));
        Ok(())
    }

    fn delete_leaf(&mut self, key: &[u8]) -> Result<(), Error> {
        self.rows.insert(leaf_key(key), None);
        Ok(())
    }
}

/// The rows as a work result's apply sees them: its writes kept apart, its
/// reads of the rows recorded.
struct Applying<'a> {
    view: &'a View,
    reads: &'a mut BTreeSet<Vec<u8>>,
    writes: Writes,
    /// A read the store failed, which spoils the apply.
    error: Option<Error>,
}

impl State for Applying<'_> {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(value) = self.writes.get(key) {
            return value.clone();
        }
        self.reads.insert(key.to_vec());
        self.view.get(key).unwrap_or_else(|error| {
            self.error.get_or_insert(error);
            None
        })
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) {
        self.writes.insert(key.to_vec(), value.map(<[u8]>::to_vec));
    }
}
