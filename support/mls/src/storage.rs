//! mls-rs's storage providers over fjall: a group's state and its key
//! packages' secrets as rows of one keyspace under a namespace's prefix.
//!
//! **Nothing mls-rs writes reaches the disk by itself.** A namespace
//! stages its writes, and [`Store::commit`] writes them and the caller's
//! own rows in one synced batch: a group's state, a held commit and the
//! caller's record of either land together or not at all.
//!
//! **A copy writes to memory alone.** A [`Namespace`] is either the current
//! one, whose writes are staged for the next batch, or a copy over it,
//! which reads through to the current rows and keeps its writes in memory:
//! a candidate processed on a copy cannot touch the current state, and
//! swapping it in moves the copy's writes into the current namespace's
//! batch.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fjall::{Database, Keyspace, PersistMode};
use mls_rs::mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use mls_rs_core::key_package::{KeyPackageData, KeyPackageStorage};
use zeroize::Zeroizing;

/// Rows a write sets (`Some`) or deletes (`None`), by key.
pub type Writes = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

/// The database and the keyspace a namespace's rows are in, beside the
/// caller's.
#[derive(Clone)]
pub struct Store {
    db: Database,
    keyspace: Keyspace,
}

impl Store {
    pub fn new(db: Database, keyspace: Keyspace) -> Self {
        Self { db, keyspace }
    }

    pub fn keyspace(&self) -> &Keyspace {
        &self.keyspace
    }

    /// Row `key` as committed.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, fjall::Error> {
        Ok(self.keyspace.get(key)?.map(|value| value.to_vec()))
    }

    /// Write `namespace`'s staged rows and `rows` in one synced batch: all
    /// of them, or, on an error, none, the staged rows kept for the next.
    pub fn commit(&self, namespace: &Namespace, rows: Writes) -> Result<(), fjall::Error> {
        let mut staged = lock(&namespace.staged);
        let mut batch = self.db.batch();
        for (key, value) in staged.iter().chain(&rows) {
            match value {
                Some(value) => batch.insert(&self.keyspace, key, value),
                None => batch.remove(&self.keyspace, key),
            }
        }
        batch.durability(Some(PersistMode::SyncAll)).commit()?;
        staged.clear();
        Ok(())
    }
}

fn lock(writes: &Mutex<Writes>) -> MutexGuard<'_, Writes> {
    writes.lock().unwrap_or_else(PoisonError::into_inner)
}

/// mls-rs's storage, a group's state and key packages, under a prefix of
/// a store's keyspace: the current namespace, or a copy over it.
#[derive(Clone)]
pub struct Namespace {
    store: Store,
    prefix: Vec<u8>,
    /// The current namespace's writes, staged for its next batch.
    staged: Arc<Mutex<Writes>>,
    /// A copy's writes, kept in memory above the current namespace's.
    copy: Option<Arc<Mutex<Writes>>>,
    /// A read that failed under mls-rs, whose errors carry nothing of a
    /// provider's: [`crate::Mls`] takes it after each call.
    failed: Arc<Mutex<Option<fjall::Error>>>,
}

impl Namespace {
    /// The current namespace under `prefix`.
    pub fn current(store: Store, prefix: Vec<u8>) -> Self {
        Self {
            store,
            prefix,
            staged: Arc::default(),
            copy: None,
            failed: Arc::default(),
        }
    }

    /// A copy over this namespace: it reads what this one holds, staged
    /// writes included, and writes to memory alone.
    pub fn copy(&self) -> Self {
        Self {
            copy: Some(Arc::default()),
            failed: Arc::default(),
            ..self.clone()
        }
    }

    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The full key of the namespace's row `name`.
    pub fn key(&self, name: &[u8]) -> Vec<u8> {
        [&self.prefix[..], name].concat()
    }

    /// Row `name` as this namespace sees it: a copy's own write, then the
    /// current namespace's staged write, then the committed row.
    pub fn get(&self, name: &[u8]) -> Result<Option<Vec<u8>>, fjall::Error> {
        let key = self.key(name);
        if let Some(copy) = &self.copy
            && let Some(value) = lock(copy).get(&key)
        {
            return Ok(value.clone());
        }
        if let Some(value) = lock(&self.staged).get(&key) {
            return Ok(value.clone());
        }
        self.store.get(&key)
    }

    /// Set (`Some`) or delete (`None`) row `name`: staged, or a copy's.
    pub fn put(&self, name: &[u8], value: Option<Vec<u8>>) {
        let key = self.key(name);
        let target = self.copy.as_ref().unwrap_or(&self.staged);
        lock(target).insert(key, value);
    }

    /// A copy's writes, taken out of it.
    pub(crate) fn take_copy(&self) -> Writes {
        self.copy
            .as_ref()
            .map(|copy| std::mem::take(&mut *lock(copy)))
            .unwrap_or_default()
    }

    /// Stage `writes`, a copy's, in the current namespace.
    pub(crate) fn stage(&self, writes: Writes) {
        lock(&self.staged).extend(writes);
    }

    /// The read that failed under mls-rs since the last take, if one did.
    pub(crate) fn take_failure(&self) -> Option<fjall::Error> {
        self.failed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take()
    }

    /// Discard the staged writes: an operation that failed before its
    /// batch leaves the current rows as they were.
    pub(crate) fn unstage(&self) {
        lock(&self.staged).clear();
    }
}

/// A group's state, by its id.
pub(crate) fn state_row(group: &[u8]) -> Vec<u8> {
    [b"state/".as_slice(), group].concat()
}

/// A key package's secrets, by its reference.
fn package_row(id: &[u8]) -> Vec<u8> {
    [b"package/".as_slice(), id].concat()
}

/// A storage read failed: what mls-rs sees. The error itself is kept in
/// the namespace.
#[derive(Debug)]
pub struct StorageError;

impl mls_rs_core::error::IntoAnyError for StorageError {}

fn read(namespace: &Namespace, name: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
    namespace.get(name).map_err(|error| {
        *namespace
            .failed
            .lock()
            .unwrap_or_else(PoisonError::into_inner) = Some(error);
        StorageError
    })
}

/// The group state alone: the device group keeps no prior epoch's secrets
/// (its data keys are exported and archived by the caller), so mls-rs's
/// epoch records, which only `prior_epoch` writes, are none.
impl GroupStateStorage for Namespace {
    type Error = StorageError;

    fn state(&self, group: &[u8]) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        Ok(read(self, &state_row(group))?.map(Zeroizing::new))
    }

    fn epoch(&self, _: &[u8], _: u64) -> Result<Option<Zeroizing<Vec<u8>>>, StorageError> {
        Ok(None)
    }

    fn max_epoch_id(&self, _: &[u8]) -> Result<Option<u64>, StorageError> {
        Ok(None)
    }

    fn write(
        &mut self,
        state: GroupState,
        _: Vec<EpochRecord>,
        _: Vec<EpochRecord>,
    ) -> Result<(), StorageError> {
        self.put(&state_row(&state.id), Some(state.data.to_vec()));
        Ok(())
    }
}

impl KeyPackageStorage for Namespace {
    type Error = StorageError;

    fn delete(&mut self, id: &[u8]) -> Result<(), StorageError> {
        self.put(&package_row(id), None);
        Ok(())
    }

    fn insert(&mut self, id: Vec<u8>, package: KeyPackageData) -> Result<(), StorageError> {
        let bytes = package.mls_encode_to_vec().map_err(|_| StorageError)?;
        self.put(&package_row(&id), Some(bytes));
        Ok(())
    }

    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, StorageError> {
        Ok(read(self, &package_row(id))?
            .and_then(|bytes| KeyPackageData::mls_decode(&mut &*bytes).ok()))
    }
}
