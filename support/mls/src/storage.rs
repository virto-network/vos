//! mls-rs's storage providers over fjall: a group's state and its key
//! packages' secrets as rows of one keyspace under a namespace's prefix.
//!
//! **Nothing mls-rs writes reaches the disk by itself.** A namespace
//! stages its writes, and its commit writes them and the caller's
//! own rows in one synced batch: a group's state, a held commit and the
//! caller's record of either land together or not at all.
//!
//! **A copy writes to memory alone.** A [`Namespace`] is either the current
//! one, whose writes are staged for the next batch, or a copy over it,
//! which reads through to the current rows and keeps its writes in memory:
//! a candidate processed on a copy cannot touch the current state, and
//! swapping it in moves the copy's writes into the current namespace's
//! batch.
//!
//! **Every key is bounded before it reaches fjall**, which takes a key of
//! 1 to 65,535 bytes and a value under 4 GiB and panics on any other: a
//! read of a key it cannot hold finds no row, a batch holding one is an
//! error and writes nothing, and a key package is looked up only by a
//! reference of the suite's hash length.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use fjall::{Database, Keyspace, PersistMode};
use mls_rs::mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use mls_rs_core::key_package::{KeyPackageData, KeyPackageStorage};
use zeroize::Zeroizing;

use crate::Error;

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

    /// Row `key` as committed: none for a key the store cannot hold.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, fjall::Error> {
        if !holds(key) {
            return Ok(None);
        }
        Ok(self.keyspace.get(key)?.map(|value| value.to_vec()))
    }
}

/// Whether fjall can hold `key`: 1 to 65,535 bytes.
fn holds(key: &[u8]) -> bool {
    !key.is_empty() && u16::try_from(key.len()).is_ok()
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
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
    failed: Arc<Mutex<Option<Error>>>,
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

    /// The full key of the namespace's row `name`.
    fn key(&self, name: &[u8]) -> Vec<u8> {
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

    /// Where this namespace's writes go: a copy's own, or staged.
    fn target(&self) -> &Mutex<Writes> {
        self.copy.as_deref().unwrap_or(&self.staged)
    }

    /// Set (`Some`) or delete (`None`) row `name`: staged, or a copy's.
    pub(crate) fn put(&self, name: &[u8], value: Option<Vec<u8>>) {
        let key = self.key(name);
        lock(self.target()).insert(key, value);
    }

    /// Write the staged rows and `rows` in one synced batch: all
    /// of them, or, on an error, none, the staged rows kept for the next.
    /// A row the store cannot hold is [`Error::Unstorable`]. A failed sync
    /// is [`Error::Store`], and fjall then takes no more writes; its
    /// journal may hold the batch, so a reopen can find it applied.
    pub(crate) fn commit(&self, rows: Writes) -> Result<(), Error> {
        let mut staged = lock(&self.staged);
        let fits = |(key, value): (&Vec<u8>, &Option<Vec<u8>>)| {
            holds(key)
                && value
                    .as_ref()
                    .is_none_or(|value| u32::try_from(value.len()).is_ok())
        };
        if !staged.iter().chain(&rows).all(fits) {
            return Err(Error::Unstorable);
        }
        let mut batch = self.store.db.batch();
        for (key, value) in staged.iter().chain(&rows) {
            match value {
                Some(value) => batch.insert(&self.store.keyspace, key, value),
                None => batch.remove(&self.store.keyspace, key),
            }
        }
        batch.durability(Some(PersistMode::SyncAll)).commit()?;
        staged.clear();
        Ok(())
    }

    /// Delete every row whose name starts with `name`, committed or
    /// staged: on the current namespace, staged for its next batch.
    pub(crate) fn delete_all(&self, name: &[u8]) -> Result<(), fjall::Error> {
        let prefix = self.key(name);
        let mut keys: Vec<Vec<u8>> = lock(&self.staged)
            .keys()
            .filter(|key| key.starts_with(&prefix))
            .cloned()
            .collect();
        for row in self.store.keyspace.prefix(&prefix) {
            keys.push(row.into_inner()?.0.to_vec());
        }
        let mut target = lock(self.target());
        for key in keys {
            target.insert(key, None);
        }
        Ok(())
    }

    /// Stage `copy`'s writes, taken out of it, in this namespace.
    pub(crate) fn stage_copy(&self, copy: &Namespace) {
        if let Some(writes) = &copy.copy {
            let writes = std::mem::take(&mut *lock(writes));
            lock(&self.staged).extend(writes);
        }
    }

    /// The read that failed under mls-rs since the last take, if one did:
    /// [`Error::Store`], or [`Error::Corrupt`] for a row that does not
    /// decode.
    pub(crate) fn take_failure(&self) -> Option<Error> {
        lock(&self.failed).take()
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

/// The rows of key packages' secrets, by reference.
pub(crate) const PACKAGES: &[u8] = b"package/";

/// A key package's secrets, by its reference.
fn package_row(id: &[u8]) -> Vec<u8> {
    [PACKAGES, id].concat()
}

/// The suite's hash length, SHA-256: a key package reference's, and the
/// longest group id a Welcome may name (the length mls-rs draws).
pub(crate) const HASH_BYTES: usize = 32;

/// A storage read failed: what mls-rs sees. The error itself is kept in
/// the namespace.
#[derive(Debug)]
pub struct StorageError;

impl mls_rs_core::error::IntoAnyError for StorageError {}

/// `error` kept in `namespace` for [`crate::Mls`] to take; what mls-rs
/// sees.
fn failed(namespace: &Namespace, error: Error) -> StorageError {
    *lock(&namespace.failed) = Some(error);
    StorageError
}

fn read(namespace: &Namespace, name: &[u8]) -> Result<Option<Vec<u8>>, StorageError> {
    namespace
        .get(name)
        .map_err(|error| failed(namespace, Error::Store(error)))
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
        if id.len() == HASH_BYTES {
            self.put(&package_row(id), None);
        }
        Ok(())
    }

    fn insert(&mut self, id: Vec<u8>, package: KeyPackageData) -> Result<(), StorageError> {
        let bytes = package.mls_encode_to_vec().map_err(|_| StorageError)?;
        self.put(&package_row(&id), Some(bytes));
        Ok(())
    }

    /// None for a reference that is not the suite's hash length; a row
    /// that does not decode is [`Error::Corrupt`].
    fn get(&self, id: &[u8]) -> Result<Option<KeyPackageData>, StorageError> {
        if id.len() != HASH_BYTES {
            return Ok(None);
        }
        read(self, &package_row(id))?
            .map(|bytes| {
                KeyPackageData::mls_decode(&mut &*bytes).map_err(|_| failed(self, Error::Corrupt))
            })
            .transpose()
    }
}
