//! redb-backed [`Store`] implementation.
//!
//! Stores DAG nodes in a redb table keyed by CID bytes. Each database
//! file can hold the DAG for one actor (or one logical CRDT).

use crate::{Cid, DagNode, Decode, Encode, Hasher, Store};

/// redb table: CID bytes → serialized DagNode.
const DAG_TABLE: redb::TableDefinition<&[u8], &[u8]> = redb::TableDefinition::new("dag");

/// A merkle-crdt [`Store`] backed by a redb database.
pub struct RedbStore<H: Hasher> {
    db: redb::Database,
    _marker: core::marker::PhantomData<H>,
}

impl<H: Hasher> RedbStore<H> {
    /// Open (or create) a redb store at the given path.
    pub fn open(path: &std::path::Path) -> Result<Self, redb::DatabaseError> {
        Ok(Self {
            db: redb::Database::create(path)?,
            _marker: core::marker::PhantomData,
        })
    }

    /// Wrap an already-open redb Database.
    pub fn from_db(db: redb::Database) -> Self {
        Self {
            db,
            _marker: core::marker::PhantomData,
        }
    }

    /// Access the underlying redb Database (e.g. to share it with
    /// other tables like actor state).
    pub fn db(&self) -> &redb::Database {
        &self.db
    }
}

/// Error type for redb store operations.
#[derive(Debug)]
pub enum RedbStoreError {
    Db(redb::DatabaseError),
    Table(redb::TableError),
    Storage(redb::StorageError),
    Transaction(redb::TransactionError),
    Commit(redb::CommitError),
    Decode,
}

impl core::fmt::Display for RedbStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Db(e) => write!(f, "redb: {e}"),
            Self::Table(e) => write!(f, "redb table: {e}"),
            Self::Storage(e) => write!(f, "redb storage: {e}"),
            Self::Transaction(e) => write!(f, "redb txn: {e}"),
            Self::Commit(e) => write!(f, "redb commit: {e}"),
            Self::Decode => write!(f, "redb: failed to decode DagNode"),
        }
    }
}

impl std::error::Error for RedbStoreError {}

impl From<redb::DatabaseError> for RedbStoreError {
    fn from(e: redb::DatabaseError) -> Self {
        Self::Db(e)
    }
}
impl From<redb::TableError> for RedbStoreError {
    fn from(e: redb::TableError) -> Self {
        Self::Table(e)
    }
}
impl From<redb::StorageError> for RedbStoreError {
    fn from(e: redb::StorageError) -> Self {
        Self::Storage(e)
    }
}
impl From<redb::TransactionError> for RedbStoreError {
    fn from(e: redb::TransactionError) -> Self {
        Self::Transaction(e)
    }
}
impl From<redb::CommitError> for RedbStoreError {
    fn from(e: redb::CommitError) -> Self {
        Self::Commit(e)
    }
}

impl<H, P> Store<H, P> for RedbStore<H>
where
    H: Hasher,
    P: Encode + Decode + Clone,
{
    type Error = RedbStoreError;

    fn get(&self, cid: &Cid<H>) -> Result<Option<DagNode<H, P>>, Self::Error> {
        let txn = self.db.begin_read()?;
        let table = match txn.open_table(DAG_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let key = cid.as_ref();
        match table.get(key)? {
            Some(val) => {
                let bytes = val.value();
                DagNode::from_bytes(bytes)
                    .map(Some)
                    .ok_or(RedbStoreError::Decode)
            }
            None => Ok(None),
        }
    }

    fn put(&mut self, cid: Cid<H>, node: DagNode<H, P>) -> Result<(), Self::Error> {
        let bytes = node.to_bytes();
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DAG_TABLE)?;
            table.insert(cid.as_ref(), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    fn contains(&self, cid: &Cid<H>) -> Result<bool, Self::Error> {
        let txn = self.db.begin_read()?;
        let table = match txn.open_table(DAG_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(false),
            Err(e) => return Err(e.into()),
        };
        Ok(table.get(cid.as_ref())?.is_some())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MerkleCrdt, Payload};
    use alloc::collections::BTreeSet;
    use alloc::format;
    use alloc::string::String;

    // Simple test hasher
    struct TestHash;
    impl Hasher for TestHash {
        type Output = [u8; 32];
        fn hash(data: &[u8]) -> [u8; 32] {
            let mut out = [0u8; 32];
            for (i, b) in data.iter().enumerate() {
                out[i % 32] ^= b;
            }
            out
        }
    }

    #[derive(Clone, Debug)]
    struct AddItem(String);

    impl Encode for AddItem {
        fn encode_to(&self, buf: &mut alloc::vec::Vec<u8>) {
            self.0.encode_to(buf);
        }
    }

    impl Decode for AddItem {
        fn decode_from(buf: &[u8], pos: &mut usize) -> Option<Self> {
            String::decode_from(buf, pos).map(AddItem)
        }
    }

    impl Payload for AddItem {
        type State = BTreeSet<String>;
        fn apply(state: &mut Self::State, op: &Self) {
            state.insert(op.0.clone());
        }
    }

    #[test]
    fn redb_store_roundtrip() {
        let dir = std::env::temp_dir().join(format!("vos_redb_test_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("test.redb");

        {
            let store = RedbStore::<TestHash>::open(&db_path).unwrap();
            let mut crdt: MerkleCrdt<TestHash, AddItem, _> = MerkleCrdt::new(store);
            crdt.apply(AddItem("apple".into())).unwrap();
            crdt.apply(AddItem("banana".into())).unwrap();
            assert_eq!(crdt.state().len(), 2);
        }

        // Reopen — nodes should be persisted
        {
            let store = RedbStore::<TestHash>::open(&db_path).unwrap();
            // Just verify we can read back the nodes
            let node_count = {
                use redb::ReadableTableMetadata;
                let txn = store.db().begin_read().unwrap();
                let table = txn.open_table(DAG_TABLE).unwrap();
                table.len().unwrap()
            };
            assert_eq!(node_count, 2, "2 nodes should be persisted");
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
