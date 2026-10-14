//! An agent's whole keyspace: its rows as stored, and one tree over them,
//! each row a leaf salted by the seed of the work result that last wrote
//! it.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use vos_tree::{Blake2b, Hash, Leaf, MemStore, salt, stored_root, update, value_hash};
use vos_wire::apply::{Host, State, apply};
use vos_wire::result::WorkResult;

/// Rows by key, each as stored.
pub type Rows = BTreeMap<Vec<u8>, Vec<u8>>;

/// Rows a work result writes: a value as stored, or (`None`) a deletion.
pub type Writes = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

/// An agent's rows and its tree.
#[derive(Clone, Debug, Default)]
pub struct Store {
    /// Shared with a simulation reading them, copied on a write.
    rows: Arc<Rows>,
    tree: MemStore,
}

impl Store {
    /// The root over the whole keyspace.
    pub fn root(&self) -> Hash {
        stored_root(&Blake2b, &self.tree).expect("a tree in memory")
    }

    pub fn rows(&self) -> &Arc<Rows> {
        &self.rows
    }

    pub fn get(&self, key: &[u8]) -> Option<&[u8]> {
        self.rows.get(key).map(Vec::as_slice)
    }

    /// A row's leaf: its salt and its value's commitment.
    pub fn leaf(&self, key: &[u8]) -> Option<Leaf> {
        self.tree.leaves.get(key).copied()
    }

    pub fn tree(&self) -> &MemStore {
        &self.tree
    }

    /// The rows applying `result` writes, each row it reads put in
    /// `reads`; `None` when it does not apply.
    pub fn writes(&self, result: &WorkResult, reads: &mut BTreeSet<Vec<u8>>) -> Option<Writes> {
        let mut applying = Applying {
            rows: &self.rows,
            reads,
            writes: Writes::new(),
        };
        apply(&mut applying, result, Host::Jam).then_some(applying.writes)
    }

    /// Commit `writes`, made by a work result with `seed`: the rows, and
    /// their leaves, each salted by it. The root after.
    pub fn commit(&mut self, writes: &Writes, seed: &[u8; 32]) -> Hash {
        let rows = Arc::make_mut(&mut self.rows);
        let mut leaves = Vec::with_capacity(writes.len());
        for (key, value) in writes {
            let leaf = value.as_ref().map(|value| {
                let salt = salt(&Blake2b, seed, key);
                Leaf {
                    salt,
                    value_hash: value_hash(&Blake2b, &salt, value),
                }
            });
            match value {
                Some(value) => rows.insert(key.clone(), value.clone()),
                None => rows.remove(key),
            };
            leaves.push((key.as_slice(), leaf));
        }
        update(&Blake2b, &mut self.tree, &leaves).expect("rows the tree takes")
    }

    /// Apply `result` to the rows and the tree: the root after; `None`,
    /// with nothing changed, when it does not apply.
    pub fn apply(&mut self, result: &WorkResult) -> Option<Hash> {
        let writes = self.writes(result, &mut BTreeSet::new())?;
        Some(self.commit(&writes, &result.seed))
    }
}

/// The rows as a work result's apply sees them: its writes kept apart, its
/// reads of the rows recorded.
struct Applying<'a> {
    rows: &'a Rows,
    reads: &'a mut BTreeSet<Vec<u8>>,
    writes: Writes,
}

impl State for Applying<'_> {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        if let Some(value) = self.writes.get(key) {
            return value.clone();
        }
        self.reads.insert(key.to_vec());
        self.rows.get(key).cloned()
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) {
        self.writes.insert(key.to_vec(), value.map(<[u8]>::to_vec));
    }
}
