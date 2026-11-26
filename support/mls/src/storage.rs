//! mls-rs's storage providers over the caller's store: a group's state
//! and its key packages' secrets as rows under a namespace's prefix.
//!
//! **Nothing mls-rs writes reaches the store by itself.** A namespace
//! stages its writes, and its commit hands them and the caller's own rows
//! to the store as one set of writes: a group's state, a held commit and
//! the caller's record of either land together or not at all.
//!
//! **A copy writes to memory alone.** A [`Namespace`] is either the current
//! one, whose writes are staged for the next commit, or a copy over it,
//! which reads through to the current rows and keeps its writes in memory:
//! a candidate processed on a copy cannot touch the current state, and
//! swapping it in moves the copy's writes into the current namespace's
//! staged ones.
//!
//! **Every key is bounded before it reaches the store**, which is only
//! handed keys of 1 to 65,535 bytes and values under 4 GiB: a read of any
//! other key finds no row without asking the store, a commit holding one
//! is [`Error::Unstorable`] and writes nothing, and a key package is
//! looked up only by a reference of the suite's hash length.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use mls_rs::mls_rs_codec::{MlsDecode, MlsEncode};
use mls_rs_core::group::{EpochRecord, GroupState, GroupStateStorage};
use mls_rs_core::key_package::{KeyPackageData, KeyPackageStorage};
use zeroize::Zeroizing;

use crate::Error;

/// Rows a write sets (`Some`) or deletes (`None`), by key.
pub type Writes = BTreeMap<Vec<u8>, Option<Vec<u8>>>;

/// The caller's store, which a namespace's rows and the caller's own are
/// in. It is only handed keys of 1 to 65,535 bytes and values under 4 GiB.
pub trait Store: Send + Sync + 'static {
    /// The error type for storage operations.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Row `key` as committed.
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Self::Error>;

    /// The keys of the committed rows that start with `prefix`.
    fn keys(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, Self::Error>;

    /// Write `writes`, all of them or none, durably before it returns. On
    /// an error, reads through this store still return the rows as they
    /// were before; the set may be found written only once the store is
    /// opened again. A caller reopens before it retries an operation.
    fn commit(&self, writes: Writes) -> Result<(), Self::Error>;
}

/// A store in memory, its handles sharing one set of rows: for tests. It
/// panics on a key or value outside the bounds a store is handed, so a
/// test finds any that reaches it.
#[derive(Clone, Debug, Default)]
pub struct MemStore {
    rows: Arc<Mutex<BTreeMap<Vec<u8>, Vec<u8>>>>,
}

impl MemStore {
    /// A store of no rows.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every committed row, keys and values.
    pub fn rows(&self) -> BTreeMap<Vec<u8>, Vec<u8>> {
        lock(&self.rows).clone()
    }
}

impl Store for MemStore {
    type Error = Infallible;

    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Infallible> {
        assert!(holds(key), "a key the store is not handed");
        Ok(lock(&self.rows).get(key).cloned())
    }

    fn keys(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, Infallible> {
        assert!(holds(prefix), "a prefix the store is not handed");
        let rows = lock(&self.rows);
        let keys = rows.range(prefix.to_vec()..).map(|(key, _)| key);
        Ok(keys
            .take_while(|key| key.starts_with(prefix))
            .cloned()
            .collect())
    }

    fn commit(&self, writes: Writes) -> Result<(), Infallible> {
        let mut rows = lock(&self.rows);
        for (key, value) in writes {
            assert!(holds(&key), "a key the store is not handed");
            assert!(
                value
                    .as_ref()
                    .is_none_or(|value| u32::try_from(value.len()).is_ok()),
                "a value the store is not handed"
            );
            match value {
                Some(value) => rows.insert(key, value),
                None => rows.remove(&key),
            };
        }
        Ok(())
    }
}

/// A [`Store`] with its error as this layer's [`Error::Store`]: what a
/// namespace holds, whatever the store's type.
trait Rows: Send + Sync {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error>;
    fn keys(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, Error>;
    fn commit(&self, writes: Writes) -> Result<(), Error>;
}

fn store_error(error: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Store(Box::new(error))
}

impl<S: Store> Rows for S {
    fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        Store::get(self, key).map_err(store_error)
    }

    fn keys(&self, prefix: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
        Store::keys(self, prefix).map_err(store_error)
    }

    fn commit(&self, writes: Writes) -> Result<(), Error> {
        Store::commit(self, writes).map_err(store_error)
    }
}

/// Whether the store is handed `key`: 1 to 65,535 bytes.
fn holds(key: &[u8]) -> bool {
    !key.is_empty() && u16::try_from(key.len()).is_ok()
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// mls-rs's storage, a group's state and key packages, under a prefix of
/// a store's keys: the current namespace, or a copy over it.
#[derive(Clone)]
pub struct Namespace {
    store: Arc<dyn Rows>,
    prefix: Vec<u8>,
    /// The current namespace's writes, staged for its next commit.
    staged: Arc<Mutex<Writes>>,
    /// A copy's writes, kept in memory above the current namespace's.
    copy: Option<Arc<Mutex<Writes>>>,
    /// A read that failed under mls-rs, whose errors carry nothing of a
    /// provider's: [`crate::Mls`] takes it after each call.
    failed: Arc<Mutex<Option<Error>>>,
}

impl Namespace {
    /// The current namespace under `prefix` of `store`.
    pub fn current(store: impl Store, prefix: Vec<u8>) -> Self {
        Self {
            store: Arc::new(store),
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
    /// current namespace's staged write, then the committed row; none for
    /// a key the store is not handed.
    pub fn get(&self, name: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let key = self.key(name);
        if let Some(copy) = &self.copy
            && let Some(value) = lock(copy).get(&key)
        {
            return Ok(value.clone());
        }
        if let Some(value) = lock(&self.staged).get(&key) {
            return Ok(value.clone());
        }
        if !holds(&key) {
            return Ok(None);
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

    /// Commit the staged rows and `rows` to the store, `rows` over the
    /// staged ones: all of them, or none, the staged rows kept. A row the
    /// store is not handed is [`Error::Unstorable`], the store's failure
    /// [`Error::Store`].
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
        let mut writes = staged.clone();
        writes.extend(rows);
        self.store.commit(writes)?;
        staged.clear();
        Ok(())
    }

    /// Delete every row whose name starts with `name`, committed or
    /// staged: on the current namespace, staged for its next commit.
    pub(crate) fn delete_all(&self, name: &[u8]) -> Result<(), Error> {
        let prefix = self.key(name);
        let mut keys: Vec<Vec<u8>> = lock(&self.staged)
            .keys()
            .filter(|key| key.starts_with(&prefix))
            .cloned()
            .collect();
        keys.extend(self.store.keys(&prefix)?);
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
    /// commit leaves the current rows as they were.
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
        .map_err(|error| failed(namespace, error))
}

/// The group state alone: this layer keeps no prior epoch's secrets (a
/// caller that needs an epoch's keys later exports and keeps them), so
/// mls-rs's epoch records, which only `prior_epoch` writes, are none.
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
