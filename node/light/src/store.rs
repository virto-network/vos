//! The light node's store: one fjall database, mended at open as the
//! node's is ([`vos_exec::store::recover`]), with three keyspaces:
//!
//! - `rows`: the local agent's rows, as `vos_wire::apply` stores them;
//! - `programs`: the programs installed, by their hash;
//! - `meta`: the store's layout, and the last operation's time and seed.
//!
//! An operation's every change, its rows, its programs and its time, is one
//! batch, synced: a process killed at any point leaves the store before the
//! operation or after it.

use std::collections::BTreeMap;
use std::ops::Bound;
use std::path::Path;
use std::sync::Arc;

use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode, Readable};
use vos_exec::{ProgramStore, StateReader};
use vos_wire::apply::State;
use vos_wire::ids::AgentId;

/// The number of the store's layout: where its rows live. A store written
/// in another is refused at open.
pub const LAYOUT: u32 = 1;

/// The block cache the store keeps by default: a phone's.
pub const CACHE_BYTES: u64 = 16 << 20;

const LAYOUT_ROW: &[u8] = b"layout";
const LAST_ROW: &[u8] = b"last";

/// An installed program: its hash and its bytes.
pub type Program = ([u8; 32], Vec<u8>);

/// One row: its key and its value.
pub type Row = (Vec<u8>, Vec<u8>);

/// Why the store cannot be used.
#[derive(Debug)]
pub enum StoreError {
    /// fjall failed.
    Fjall(fjall::Error),
    /// The store names another layout, `None` for one that holds rows and
    /// names none, or whose layout row does not read.
    Layout(Option<u32>),
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
            db,
        }));
        store.check_layout()?;
        Ok(store)
    }

    /// The layout row checked, and written, synced, to a store holding
    /// nothing yet.
    fn check_layout(&self) -> Result<(), StoreError> {
        let Keyspaces {
            db,
            rows,
            programs,
            meta,
        } = &*self.0;
        match meta.get(LAYOUT_ROW)? {
            Some(value) => match <[u8; 4]>::try_from(&value[..]).map(u32::from_be_bytes) {
                Ok(LAYOUT) => Ok(()),
                Ok(layout) => Err(StoreError::Layout(Some(layout))),
                Err(_) => Err(StoreError::Layout(None)),
            },
            None if rows.is_empty()? && programs.is_empty()? && meta.is_empty()? => {
                meta.insert(LAYOUT_ROW, LAYOUT.to_be_bytes())?;
                db.persist(PersistMode::SyncAll)?;
                Ok(())
            }
            None => Err(StoreError::Layout(None)),
        }
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
        let mut last = operation.time.to_le_bytes().to_vec();
        last.extend_from_slice(&operation.seed);
        batch.insert(meta, LAST_ROW, last);
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

/// The programs installed, the local agent's every one.
impl ProgramStore for Store {
    fn get(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        self.0
            .programs
            .get(hash)
            .expect("a program read")
            .map(|bytes| bytes.to_vec())
    }

    fn pinned_by(&self, hash: &[u8; 32], _: AgentId) -> bool {
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

    /// The last operation's time and seed; none before the first.
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
    fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.get(key).expect("a store read")
    }

    fn rows<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + 'a> {
        let start = match after {
            Some(after) if after >= prefix => Bound::Excluded(after.to_vec()),
            _ => Bound::Included(prefix.to_vec()),
        };
        Box::new(
            self.snapshot
                .range(&self.store.0.rows, (start, Bound::<Vec<u8>>::Unbounded))
                .map(|row| row.into_inner().expect("a store read"))
                .take_while(move |(key, _)| key.starts_with(prefix))
                .map(|(key, value)| (key.to_vec(), value.to_vec())),
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
            None => self.snapshot.read(key),
        }
    }

    fn write(&mut self, key: &[u8], value: Option<&[u8]>) {
        self.written.insert(key.to_vec(), value.map(<[u8]>::to_vec));
    }
}
