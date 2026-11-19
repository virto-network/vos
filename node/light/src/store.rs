//! The light node's store: one fjall database, mended at open as the
//! node's is ([`vos_exec::store::recover`]), with three keyspaces of its
//! own:
//!
//! - `rows`: the local agent's rows, as `vos_wire::apply` stores them, and
//!   each scope's rows beside them: its merge fields' entries, its nodes'
//!   Lamport clocks, its authors' cutoffs and its held operations;
//! - `programs`: the programs installed, by their hash;
//! - `meta`: the store's layout, its author key, and the last local
//!   operation's time and seed;
//! - `group`: the device group's (`crate::group`): its MLS state, what it
//!   keeps of the control log, and the key archive, whose naming secret is
//!   drawn with the store and names every scope;
//!
//! and each scope's keyspaces, its DAG's (`merkle_crdt::FjallStore`),
//! named after it.
//!
//! An operation's every change, its rows, its programs, its time, and a
//! scope's nodes and their rows, is one batch, synced: a process killed at
//! any point leaves the store before the operation or after it.

use std::collections::BTreeMap;
use std::ops::Bound;
use std::path::Path;
use std::sync::Arc;

use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode, Readable};
use vos_abi::ids::{AgentId, InstanceId};
use vos_abi::{Decode, Encode};
use vos_exec::{ProgramStore, StateReader, value_window};
use vos_wire::apply::State;

use crate::group::Archive;

/// The number of the store's layout: where its rows live, and how the
/// personal space's rows encode (`crate::space`). A store written in
/// another is refused at open. Numbered apart from the node's store's
/// layouts.
pub const LAYOUT: u32 = 9;

/// The block cache the store keeps by default: a phone's.
pub const CACHE_BYTES: u64 = 16 << 20;

const LAYOUT_ROW: &[u8] = b"layout";
const LAST_ROW: &[u8] = b"last";
const AUTHOR_ROW: &[u8] = b"author";
/// The key archive, in the group keyspace.
pub(crate) const ARCHIVE_ROW: &[u8] = b"g/archive";
/// Set once a scope's id is derived from the archive's naming secret.
const SCOPED_ROW: &[u8] = b"g/scoped";
/// The push queue's rows, in the meta keyspace: an instance's sealed
/// envelopes by its nodes' sequence numbers.
const QUEUE: &[u8] = b"queue/";

/// An installed program: its hash and its bytes.
pub type Program = ([u8; 32], Vec<u8>);

/// One row: its key and its value.
pub type Row = (Vec<u8>, Vec<u8>);

/// A row's change: its key and its new value, `None` deleting it.
pub type Change = (Vec<u8>, Option<Vec<u8>>);

/// Why the store cannot be used.
#[derive(Debug)]
pub enum StoreError {
    /// fjall failed.
    Fjall(fjall::Error),
    /// The store names another layout, `None` for one that holds rows and
    /// names none, or whose layout row does not read.
    Layout(Option<u32>),
    /// The operating system had no randomness for a new store's author
    /// key or naming secret.
    Randomness,
}

impl From<fjall::Error> for StoreError {
    fn from(error: fjall::Error) -> Self {
        StoreError::Fjall(error)
    }
}

impl From<std::io::Error> for StoreError {
    fn from(error: std::io::Error) -> Self {
        StoreError::Fjall(error.into())
    }
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Fjall(error) => write!(f, "the store: {error}"),
            StoreError::Layout(Some(layout)) => write!(
                f,
                "the store is laid out as layout {layout}, and this build reads layout {LAYOUT}"
            ),
            StoreError::Layout(None) => f.write_str("the store names no layout it can read"),
            StoreError::Randomness => f.write_str("no randomness for a new store's secrets"),
        }
    }
}

/// The light node's store: a handle, its clones sharing one database.
#[derive(Clone)]
pub struct Store(Arc<Keyspaces>);

struct Keyspaces {
    db: Database,
    rows: Keyspace,
    programs: Keyspace,
    meta: Keyspace,
    group: Keyspace,
}

impl Store {
    /// Open the store at `dir`, with a block cache of `cache_bytes`.
    pub fn open(dir: &Path, cache_bytes: u64) -> Result<Self, StoreError> {
        vos_exec::store::recover(dir)?;
        let db = Database::builder(dir).cache_size(cache_bytes).open()?;
        let store = Store(Arc::new(Keyspaces {
            rows: db.keyspace("rows", KeyspaceCreateOptions::default)?,
            programs: db.keyspace("programs", KeyspaceCreateOptions::default)?,
            meta: db.keyspace("meta", KeyspaceCreateOptions::default)?,
            group: db.keyspace("group", KeyspaceCreateOptions::default)?,
            db,
        }));
        store.check_layout()?;
        Ok(store)
    }

    /// The layout row checked, and written, synced, with a fresh author
    /// key and a key archive of a fresh naming secret, to a store holding
    /// nothing yet: a store made anew, by an install or a restore, signs as
    /// a new author.
    fn check_layout(&self) -> Result<(), StoreError> {
        let Keyspaces {
            db,
            rows,
            programs,
            meta,
            group,
        } = &*self.0;
        match meta.get(LAYOUT_ROW)? {
            Some(value) => match <[u8; 4]>::try_from(&value[..]).map(u32::from_be_bytes) {
                Ok(LAYOUT) => Ok(()),
                Ok(layout) => Err(StoreError::Layout(Some(layout))),
                Err(_) => Err(StoreError::Layout(None)),
            },
            None if rows.is_empty()?
                && programs.is_empty()?
                && meta.is_empty()?
                && group.is_empty()? =>
            {
                let mut seed = zeroize::Zeroizing::new([0u8; 32]);
                getrandom::getrandom(&mut seed[..]).map_err(|_| StoreError::Randomness)?;
                let archive = Archive::fresh().ok_or(StoreError::Randomness)?;
                let mut batch = db.batch();
                batch.insert(meta, AUTHOR_ROW, &seed[..]);
                batch.insert(group, ARCHIVE_ROW, archive.encode());
                batch.insert(meta, LAYOUT_ROW, LAYOUT.to_be_bytes());
                batch.durability(Some(PersistMode::SyncAll)).commit()?;
                Ok(())
            }
            None => Err(StoreError::Layout(None)),
        }
    }

    /// The store's author key: the seed of the ed25519 key its scopes'
    /// nodes are signed with, drawn when the store was made.
    pub(crate) fn author(&self) -> Result<zeroize::Zeroizing<[u8; 32]>, StoreError> {
        let bytes = self
            .0
            .meta
            .get(AUTHOR_ROW)?
            .ok_or(StoreError::Layout(None))?;
        let seed = <[u8; 32]>::try_from(&bytes[..]).map_err(|_| StoreError::Layout(None))?;
        Ok(zeroize::Zeroizing::new(seed))
    }

    /// The database, which each scope's keyspaces are in.
    pub(crate) fn database(&self) -> &Database {
        &self.0.db
    }

    /// The device group's keyspace, as `vos-mls` stores in it.
    pub fn group_store(&self) -> vos_mls::Store {
        vos_mls::Store::new(self.0.db.clone(), self.0.group.clone())
    }

    /// The device group's row `key`.
    pub(crate) fn group_row(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self.0.group.get(key)?.map(|value| value.to_vec()))
    }

    /// The key archive.
    pub fn archive(&self) -> Result<Archive, StoreError> {
        let bytes = self
            .group_row(ARCHIVE_ROW)?
            .ok_or(StoreError::Layout(None))?;
        Archive::decode_exact(&bytes).ok_or(StoreError::Layout(None))
    }

    /// Whether a scope's id was derived from the archive's naming secret.
    pub(crate) fn scoped(&self) -> Result<bool, StoreError> {
        Ok(self.0.group.contains_key(SCOPED_ROW)?)
    }

    /// The id of the scope named `name`, from the archive's naming secret:
    /// from now the naming secret is this store's for good.
    pub(crate) fn scope_id(&self, name: &[u8]) -> Result<[u8; 16], StoreError> {
        let id = self.archive()?.scope(name);
        if !self.scoped()? {
            let mut batch = self.0.db.batch();
            batch.insert(&self.0.group, SCOPED_ROW, []);
            batch.durability(Some(PersistMode::SyncAll)).commit()?;
        }
        Ok(id)
    }

    /// Take `archive` as this store's, as a paired device takes the pairing
    /// device's: only while no scope's id was derived from the naming
    /// secret it holds.
    pub fn adopt(&self, archive: &Archive) -> Result<bool, StoreError> {
        if self.scoped()? {
            return Ok(false);
        }
        let mut batch = self.0.db.batch();
        batch.insert(&self.0.group, ARCHIVE_ROW, archive.encode());
        batch.durability(Some(PersistMode::SyncAll)).commit()?;
        Ok(true)
    }

    /// The group keyspace's rows under `prefix`, after `after` if given,
    /// in order.
    pub(crate) fn group_rows(
        &self,
        prefix: &[u8],
        after: Option<&[u8]>,
    ) -> Result<Vec<Row>, StoreError> {
        let start = match after {
            Some(after) => Bound::Excluded(after.to_vec()),
            None => Bound::Included(prefix.to_vec()),
        };
        let mut rows = Vec::new();
        for row in self.0.group.range::<Vec<u8>, _>((start, Bound::Unbounded)) {
            let (key, value) = row.into_inner()?;
            if !key.starts_with(prefix) {
                break;
            }
            rows.push((key.to_vec(), value.to_vec()));
        }
        Ok(rows)
    }

    /// Write `rows` of the group keyspace, synced: `None` deletes.
    pub(crate) fn write_group_rows(&self, rows: Vec<Change>) -> Result<(), StoreError> {
        let mut batch = self.0.db.batch();
        for (key, value) in rows {
            match value {
                Some(value) => batch.insert(&self.0.group, key, value),
                None => batch.remove(&self.0.group, key),
            }
        }
        Ok(batch.durability(Some(PersistMode::SyncAll)).commit()?)
    }

    /// The push queue's key for `instance`'s node `seq`, in the meta
    /// keyspace.
    pub(crate) fn queue_key(&self, instance: InstanceId, seq: u64) -> (&Keyspace, Vec<u8>) {
        let mut key = QUEUE.to_vec();
        key.extend_from_slice(&instance.0.to_be_bytes());
        key.extend_from_slice(&seq.to_be_bytes());
        (&self.0.meta, key)
    }

    /// `instance`'s queued envelopes, by their nodes' sequence numbers.
    pub(crate) fn queued(&self, instance: InstanceId) -> Result<Vec<(u64, Vec<u8>)>, StoreError> {
        let (_, prefix) = self.queue_key(instance, 0);
        let prefix = &prefix[..QUEUE.len() + 4];
        let mut queued = Vec::new();
        for row in self.0.meta.prefix(prefix) {
            let (key, value) = row.into_inner()?;
            let seq =
                <[u8; 8]>::try_from(&key[prefix.len()..]).map_err(|_| StoreError::Layout(None))?;
            queued.push((u64::from_be_bytes(seq), value.to_vec()));
        }
        Ok(queued)
    }

    /// Write `instance`'s queue rows, synced: each node's sealed envelope,
    /// or (`None`) its deletion.
    pub(crate) fn write_queue(
        &self,
        instance: InstanceId,
        rows: impl IntoIterator<Item = (u64, Option<Vec<u8>>)>,
    ) -> Result<(), StoreError> {
        let mut batch = self.0.db.batch();
        for (seq, value) in rows {
            let (meta, key) = self.queue_key(instance, seq);
            match value {
                Some(value) => batch.insert(meta, key, value),
                None => batch.remove(meta, key),
            }
        }
        Ok(batch.durability(Some(PersistMode::SyncAll)).commit()?)
    }

    /// The local agent's rows' keyspace, a scope's rows too.
    pub(crate) fn rows_keyspace(&self) -> &Keyspace {
        &self.0.rows
    }

    /// The meta keyspace, and the row of a local operation's time and
    /// seed in it, as an operation stages it.
    pub(crate) fn last_row(
        &self,
        time: u64,
        seed: &[u8; 32],
    ) -> (&Keyspace, &'static [u8], Vec<u8>) {
        let mut last = time.to_le_bytes().to_vec();
        last.extend_from_slice(seed);
        (&self.0.meta, LAST_ROW, last)
    }

    /// Write `changes` to the local agent's rows, synced: `None` deletes.
    pub(crate) fn write_changes(
        &self,
        changes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    ) -> Result<(), StoreError> {
        let mut batch = self.0.db.batch();
        for (key, value) in changes {
            match value {
                Some(value) => batch.insert(&self.0.rows, key, value),
                None => batch.remove(&self.0.rows, key),
            }
        }
        Ok(batch.durability(Some(PersistMode::SyncAll)).commit()?)
    }

    /// Write `rows` of the local agent's, synced.
    pub(crate) fn write_rows(&self, rows: Vec<(Vec<u8>, Vec<u8>)>) -> Result<(), StoreError> {
        let mut batch = self.0.db.batch();
        for (key, value) in rows {
            batch.insert(&self.0.rows, key, value);
        }
        Ok(batch.durability(Some(PersistMode::SyncAll)).commit()?)
    }

    /// A view of the store as it stands, which later commits do not move.
    pub fn snapshot(&self) -> Snapshot {
        Snapshot {
            store: self.clone(),
            snapshot: self.0.db.snapshot(),
        }
    }

    /// Every program installed, with its hash.
    pub fn programs(&self) -> Result<Vec<Program>, StoreError> {
        let mut programs = Vec::new();
        for row in self.0.programs.iter() {
            let (hash, bytes) = row.into_inner()?;
            let hash = <[u8; 32]>::try_from(&hash[..]).map_err(|_| StoreError::Layout(None))?;
            programs.push((hash, bytes.to_vec()));
        }
        Ok(programs)
    }

    /// Commit `operation`, synced: all of it, or, on an error, none.
    pub(crate) fn commit(&self, operation: Operation) -> Result<(), StoreError> {
        let Keyspaces {
            db,
            rows,
            programs,
            meta,
            ..
        } = &*self.0;
        let mut batch = db.batch();
        for (key, value) in operation.rows {
            match value {
                Some(value) => batch.insert(rows, key, value),
                None => batch.remove(rows, key),
            }
        }
        for (hash, program) in operation.programs {
            batch.insert(programs, hash, program);
        }
        let (_, key, last) = self.last_row(operation.time, &operation.seed);
        batch.insert(meta, key, last);
        Ok(batch.durability(Some(PersistMode::SyncAll)).commit()?)
    }

    /// Every row of the local agent, in key order: for a test's look at
    /// what the store holds.
    pub fn rows(&self) -> Result<Vec<Row>, StoreError> {
        let mut all = Vec::new();
        for row in self.0.rows.iter() {
            let (key, value) = row.into_inner()?;
            all.push((key.to_vec(), value.to_vec()));
        }
        Ok(all)
    }
}

/// The programs installed, the local agent's every one: the store holds one
/// agent, and nothing uninstalls, so each stored program is pinned.
impl ProgramStore for Store {
    fn get(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.0
            .programs
            .get(hash)
            .expect("a program read")
            .map(|bytes| bytes.to_vec())
    }

    fn pinned_by(&self, hash: &[u8; 32], agent: AgentId) -> bool {
        debug_assert_eq!(agent, crate::LOCAL);
        self.0.programs.contains_key(hash).expect("a program read")
    }
}

/// What one operation writes: the rows it sets or (`None`) deletes, the
/// programs it installs, and its time and seed.
pub(crate) struct Operation {
    pub(crate) rows: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
    pub(crate) programs: Vec<Program>,
    pub(crate) time: u64,
    pub(crate) seed: [u8; 32],
}

/// The store as of one moment.
pub struct Snapshot {
    store: Store,
    snapshot: fjall::Snapshot,
}

impl Snapshot {
    /// The local agent's row `key`.
    pub fn get(&self, key: &[u8]) -> Result<Option<Vec<u8>>, StoreError> {
        Ok(self
            .snapshot
            .get(&self.store.0.rows, key)?
            .map(|value| value.to_vec()))
    }

    /// The local agent's rows whose key starts with `prefix`, in key order,
    /// after `after` when given, each with its value. A read that fails
    /// panics, as [`StateReader`]'s do.
    pub fn scan<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> impl Iterator<Item = (Vec<u8>, fjall::Slice)> + 'a {
        let start = match after {
            Some(after) if after >= prefix => Bound::Excluded(after.to_vec()),
            _ => Bound::Included(prefix.to_vec()),
        };
        self.snapshot
            .range(&self.store.0.rows, (start, Bound::<Vec<u8>>::Unbounded))
            .map(|row| row.into_inner().expect("a store read"))
            .take_while(move |(key, _)| key.starts_with(prefix))
            .map(|(key, value)| (key.to_vec(), value))
    }

    /// The last local operation's time and seed; none before the first.
    pub fn last(&self) -> Result<Option<(u64, [u8; 32])>, StoreError> {
        let Some(bytes) = self.snapshot.get(&self.store.0.meta, LAST_ROW)? else {
            return Ok(None);
        };
        let (time, seed) = bytes
            .split_first_chunk::<8>()
            .ok_or(StoreError::Layout(None))?;
        let seed = <[u8; 32]>::try_from(seed).map_err(|_| StoreError::Layout(None))?;
        Ok(Some((u64::from_le_bytes(*time), seed)))
    }
}

/// The local agent's rows, as the agent program reads them. A read that
/// fails panics, which the light node answers as a fault.
impl StateReader for Snapshot {
    fn read(&self, key: &[u8], offset: usize, max: usize) -> Option<(usize, Vec<u8>)> {
        let value = self.get(key).expect("a store read")?;
        Some(value_window(&value, offset, max))
    }

    fn rows<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> Box<dyn Iterator<Item = (Vec<u8>, usize)> + 'a> {
        Box::new(
            self.scan(prefix, after)
                .map(|(key, value)| (key, value.len())),
        )
    }
}

/// A snapshot under the writes an apply makes, which its later reads see.
pub(crate) struct Applying<'a> {
    pub(crate) snapshot: &'a Snapshot,
    pub(crate) written: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl State for Applying<'_> {
    fn read(&mut self, key: &[u8]) -> Option<Vec<u8>> {
        match self.written.get(key) {
            Some(value) => value.clone(),
            None => self.snapshot.get(key).expect("a store read"),
        }
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) {
        self.written.insert(key.to_vec(), value.map(<[u8]>::to_vec));
    }
}
