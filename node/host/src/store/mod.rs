//! The node's storage: one LSM keyspace with four partitions.
//!
//! - `state`: agents' instance rows, keyed by agent and epoch, then the
//!   agent-relative key;
//! - `system`: agents' system keys (sessions, reply windows, pair marks,
//!   the outbox), keyed the same way, and the node's own rows for each
//!   agent (its applied index, its Raft state), above every epoch, with
//!   the store's layout row, which [`Fjall::open`] checks;
//! - `log`: each agent's log, by (agent, index);
//! - `blobs`: the blob store's index and pins ([`crate::blobs`]).
//!
//! An agent's rows live under an epoch, so that a snapshot can be installed
//! beside the current state and switched to at once: one synced batch moves
//! the agent's epoch pointer, and reads go through it.
//!
//! Writes go through a [`Batch`]; the storage thread folds the changes of
//! several commits, of any agents, into one. A replicated agent appends
//! with a sync before applying, and applies without one.

mod batch;
mod entry;
mod keys;
mod read;
#[cfg(test)]
mod tests;
mod tuning;

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use fjall::{Database, Keyspace, KeyspaceCreateOptions, Readable};
use vos_wire::Decode;
use vos_wire::ids::AgentId;
use vos_wire::peer::{CreationRecord, Placement};

use crate::blobs::{IndexRow, pinned_hash};

use keys::{
    NODE, NodeRow, SYSTEM, agent_key, applied, be_u64, decode_entry, decode_hard,
    decode_membership, decode_position, entry_blobs, epoch, log_index, log_key, node_record,
    node_row, prover_job, prover_job_of, registry_prefix,
};

pub use batch::Batch;
pub use entry::{BlobRef, EntryKind, LARGE_RESULT, LogEntry};
pub use fjall::{Error, PersistMode};
pub use keys::{LAYOUT, NODE_AGENT, decode_configuration, encode_configuration, next_epoch};
pub use read::{Export, Snapshot};
pub use tuning::Tuning;
pub use vos_wire::peer::NodeNumber;

pub type Result<T> = std::result::Result<T, Error>;

/// One of an agent's rows: its agent-relative key and its value.
pub type Row = (Vec<u8>, Vec<u8>);

/// A replica's term, vote and commit index.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct HardState {
    pub term: u64,
    pub vote: Option<NodeNumber>,
    pub commit: u64,
}

/// An agent's replica set as the replica last adopted it, and the index of
/// the entry that established it, when known.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Membership {
    pub index: Option<u64>,
    pub members: Vec<NodeNumber>,
    pub joint_old: Option<Vec<NodeNumber>>,
}

/// An agent's epoch, applied index and log start.
pub(crate) struct AgentRows {
    pub(crate) epoch: u8,
    pub(crate) applied: u64,
    pub(crate) log_start: u64,
}

/// A snapshot switch's rows.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Switch {
    pub epoch: u8,
    pub index: u64,
    pub term: u64,
    pub hard: HardState,
    pub membership: Membership,
    pub log_start_membership: Option<Membership>,
    pub truncate_after: Option<u64>,
}

/// What a replica recovers of its agent's Raft state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RaftRows {
    pub hard: HardState,
    /// The index and term the log starts after: where it was compacted to,
    /// or a snapshot installed at.
    pub log_start: (u64, u64),
    /// The replica set in effect at the log's start.
    pub log_start_membership: Option<Membership>,
    pub membership: Option<Membership>,
    pub applied: u64,
    /// The log after its start, in order.
    pub log: Vec<(u64, LogEntry)>,
    /// The last log position (index, term) held before a retirement wiped
    /// the log: if the agent is added here again, this replica votes only
    /// for candidates whose log reaches it.
    pub vote_floor: Option<(u64, u64)>,
}

/// The fjall-backed store: a handle, its clones sharing one database.
#[derive(Clone)]
pub struct Fjall(Arc<Partitions>);

/// The store's database and its partitions.
struct Partitions {
    db: Database,
    state: Keyspace,
    system: Keyspace,
    log: Keyspace,
    blobs: Keyspace,
}

/// A row of [`Fjall::dump`]: its partition's name, its key and its value.
#[cfg(feature = "dump")]
pub type DumpedRow = (&'static str, Vec<u8>, Vec<u8>);

/// A prover's job as the store keeps it: its agent, its statement's id and
/// its encoding.
pub type ProverJob = (AgentId, [u8; 32], Vec<u8>);

impl Fjall {
    /// Open the store at `path`. Everything it will recover is synced
    /// first: rows a crashed process left in the page cache could otherwise
    /// still be lost to a power cut after the node relied on them. (This
    /// rests on fjall 3.1's files: it syncs its tables and a journal before
    /// rotating it, so only journals can hold unsynced rows. Re-check it on
    /// an upgrade.)
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_tuned(path, Tuning::default())
    }

    fn partition(&self, key: &[u8]) -> &Keyspace {
        match key.first() {
            Some(&SYSTEM) => self.system(),
            _ => self.state(),
        }
    }

    pub(crate) fn last_log_index(&self, agent: AgentId) -> Result<Option<u64>> {
        let prefix = agent.0.to_be_bytes();
        match self.log().prefix(prefix).next_back() {
            Some(row) => Ok(log_index(&row.key()?)),
            None => Ok(None),
        }
    }

    /// Whether the agent has rows under `epoch`.
    pub(crate) fn epoch_holds_rows(&self, agent: AgentId, epoch: u8) -> Result<bool> {
        let prefix = agent_key(agent, epoch, &[]);
        for partition in [self.system(), self.state()] {
            if let Some(row) = partition.prefix(&prefix).next() {
                row.key()?;
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// An agent's epoch, applied index and log start, as stored.
    pub(crate) fn agent_rows(&self, agent: AgentId) -> Result<AgentRows> {
        let row = |kind| self.system().get(node_row(agent, kind));
        Ok(AgentRows {
            epoch: epoch(row(NodeRow::Epoch)?),
            applied: applied(row(NodeRow::Applied)?).unwrap_or(0),
            log_start: row(NodeRow::LogStart)?
                .and_then(|bytes| be_u64(bytes.get(..8)?))
                .unwrap_or(0),
        })
    }

    pub(crate) fn database(&self) -> &Database {
        &self.0.db
    }

    pub(crate) fn blobs(&self) -> &Keyspace {
        &self.0.blobs
    }

    fn state(&self) -> &Keyspace {
        &self.0.state
    }

    fn system(&self) -> &Keyspace {
        &self.0.system
    }

    fn log(&self) -> &Keyspace {
        &self.0.log
    }

    /// Every blob a log row names or a pin holds, as `snapshot` sees them.
    pub(crate) fn referenced_blobs(&self, snapshot: &fjall::Snapshot) -> Result<HashSet<[u8; 32]>> {
        let mut referenced = HashSet::new();
        for row in snapshot.iter(self.log()) {
            let blobs = entry_blobs(&row.value()?).expect("a log entry this store wrote");
            referenced.extend(blobs.iter().map(|blob| blob.hash));
        }
        for row in snapshot.prefix(self.blobs(), [IndexRow::Pin as u8]) {
            referenced.insert(pinned_hash(&row.key()?));
        }
        Ok(referenced)
    }

    pub fn log_entry(&self, agent: AgentId, index: u64) -> Result<Option<LogEntry>> {
        Ok(self
            .log()
            .get(log_key(agent, index))?
            .map(|bytes| decode_entry(&bytes).expect("a log entry this store wrote")))
    }

    /// Entries `from..=to`, in order, within `max_bytes` but at least one
    /// when any is stored.
    pub fn log_range(
        &self,
        agent: AgentId,
        from: u64,
        to: u64,
        max_bytes: usize,
    ) -> Result<Vec<(u64, LogEntry)>> {
        let mut out = Vec::new();
        let mut bytes = 0;
        if from > to {
            return Ok(out);
        }
        for row in self.log().range(log_key(agent, from)..=log_key(agent, to)) {
            let (key, value) = row.into_inner()?;
            if !out.is_empty() && bytes + value.len() > max_bytes {
                break;
            }
            bytes += value.len();
            let index = log_index(&key).expect("an 8-byte log index");
            let entry = decode_entry(&value).expect("a log entry this store wrote");
            out.push((index, entry));
        }
        Ok(out)
    }

    /// The agent's Raft state, for recovery.
    pub fn raft(&self, agent: AgentId) -> Result<RaftRows> {
        let row = |kind| self.system().get(node_row(agent, kind));
        let hard = row(NodeRow::Hard)?
            .and_then(|bytes| decode_hard(&bytes))
            .unwrap_or_default();
        let start_row = row(NodeRow::LogStart)?;
        let log_start = start_row
            .as_ref()
            .and_then(|bytes| decode_position(bytes))
            .unwrap_or((0, 0));
        let log_start_membership = start_row
            .as_ref()
            .and_then(|bytes| decode_membership(bytes.get(16..)?));
        let membership = row(NodeRow::Membership)?.and_then(|bytes| decode_membership(&bytes));
        let applied = applied(row(NodeRow::Applied)?).unwrap_or(0);
        let log = self.log_range(agent, log_start.0 + 1, u64::MAX, usize::MAX)?;
        let vote_floor = row(NodeRow::VoteFloor)?.and_then(|bytes| decode_position(&bytes));
        Ok(RaftRows {
            hard,
            log_start,
            log_start_membership,
            membership,
            applied,
            log,
            vote_floor,
        })
    }

    /// The seed of the node's key, once made: secret, never served.
    pub fn node_secret(&self) -> Result<Option<[u8; 32]>> {
        Ok(self
            .system()
            .get(node_record(NodeRow::Secret, &[]))?
            .and_then(|seed| seed[..].try_into().ok()))
    }

    /// Every key and value of every partition, by partition, in key order:
    /// all the store holds, as a test reads it, however its blocks are
    /// compressed on disk.
    #[cfg(feature = "dump")]
    pub fn dump(&self) -> Result<Vec<DumpedRow>> {
        let partitions = [
            ("state", &self.0.state),
            ("system", &self.0.system),
            ("log", &self.0.log),
            ("blobs", &self.0.blobs),
        ];
        let mut rows = Vec::new();
        for (name, partition) in partitions {
            for row in partition.iter() {
                let (key, value) = row.into_inner()?;
                rows.push((name, key.to_vec(), value.to_vec()));
            }
        }
        Ok(rows)
    }

    /// The prover's jobs, each its agent, its statement's id and its
    /// encoding, by agent and id.
    pub fn prover_jobs(&self) -> Result<Vec<ProverJob>> {
        let prefix = node_record(NodeRow::ProverJob, &[]);
        let mut jobs = Vec::new();
        for row in self.system().prefix(&prefix) {
            let (key, job) = row.into_inner()?;
            let Some((agent, id)) = prover_job_of(&key[prefix.len()..]) else {
                tracing::error!("a prover's job is misnamed; it is not read");
                continue;
            };
            jobs.push((agent, id, job.to_vec()));
        }
        Ok(jobs)
    }

    /// The prover's job of `agent`'s statement `id`, its encoding.
    pub fn prover_job(&self, agent: AgentId, id: &[u8; 32]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .system()
            .get(prover_job(agent, id))?
            .map(|job| job.to_vec()))
    }

    /// Whether the node was stopping when it last ran, for its prover's
    /// table.
    pub fn prover_stopping(&self) -> Result<bool> {
        Ok(self
            .system()
            .get(node_record(NodeRow::ProverStopping, &[]))?
            .is_some())
    }

    /// The node's last run, as its pair heartbeat numbered it.
    pub fn incarnation(&self) -> Result<u64> {
        Ok(self
            .system()
            .get(node_record(NodeRow::Incarnation, &[]))?
            .and_then(|value| value[..].try_into().ok())
            .map_or(0, u64::from_be_bytes))
    }

    /// Epochs other than the agent's current one that still hold rows.
    pub fn stale_epochs(&self, agent: AgentId) -> Result<Vec<u8>> {
        let current = epoch(self.system().get(node_row(agent, NodeRow::Epoch))?);
        let mut stale = Vec::new();
        for epoch in (0..NODE).filter(|&epoch| epoch != current) {
            if self.epoch_holds_rows(agent, epoch)? {
                stale.push(epoch);
            }
        }
        Ok(stale)
    }

    /// The agents this node knows, each with its creation record.
    pub fn agents(&self) -> Result<Vec<CreationRecord>> {
        let prefix = registry_prefix();
        let mut records = Vec::new();
        for row in self.system().prefix(&prefix) {
            let (key, value) = row.into_inner()?;
            match CreationRecord::decode_exact(&value) {
                Some(record) => records.push(record),
                None => tracing::error!(
                    key = ?&key[prefix.len()..],
                    "an unreadable creation record; its agent is not run"
                ),
            }
        }
        Ok(records)
    }

    /// Every agent's latest placement this node holds: `None` where its
    /// row is unreadable.
    pub fn placements(&self) -> Result<HashMap<AgentId, Option<Placement>>> {
        let prefix = node_record(NodeRow::Placement, &[]);
        let mut placements = HashMap::new();
        for row in self.system().prefix(&prefix) {
            let (key, value) = row.into_inner()?;
            let Some(agent) = key
                .get(prefix.len()..)
                .and_then(|id| id.try_into().ok())
                .map(|id| AgentId(u32::from_be_bytes(id)))
            else {
                tracing::error!(key = ?&key[prefix.len()..], "an unreadable placement key");
                continue;
            };
            placements.insert(agent, Placement::decode_exact(&value));
        }
        Ok(placements)
    }
}

/// Sync every journal file under `dir`, and the directories holding them.
fn sync_journals(dir: &Path) -> Result<()> {
    let mut pending = vec![dir.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let mut journals = false;
        for entry in std::fs::read_dir(&dir)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|extension| extension == "jnl") {
                std::fs::File::open(&path)?.sync_all()?;
                journals = true;
            }
        }
        if journals {
            std::fs::File::open(&dir)?.sync_all()?;
        }
    }
    Ok(())
}

/// Clear a store fjall began creating and never finished: one whose
/// `version` marker, which fjall writes last, is missing or empty. Such a
/// store holds no data, but fjall takes it for a new one and its creation
/// fails on the journal or lock the interrupted creation left
/// (`AlreadyExists`), so a node killed during its store's creation could
/// never open it again. fjall's own entries (its journals, its lock, its
/// keyspaces' folder and the empty marker) are removed, and the directory
/// synced, so the creation starts over.
fn clear_unfinished(dir: &Path) -> Result<()> {
    let finished = std::fs::metadata(dir.join("version")).is_ok_and(|marker| marker.len() > 0);
    if finished {
        return Ok(());
    }
    let mut cleared = false;
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("");
        if name == "keyspaces" && path.is_dir() {
            std::fs::remove_dir_all(&path)?;
        } else if name == "lock"
            || name == "version"
            || path.extension().is_some_and(|extension| extension == "jnl")
        {
            std::fs::remove_file(&path)?;
        } else {
            continue;
        }
        cleared = true;
    }
    if cleared {
        tracing::warn!(?dir, "cleared a store whose creation was cut short");
        std::fs::File::open(dir)?.sync_all()?;
    }
    Ok(())
}

impl Fjall {
    /// Open the store at `path` with `tuning`, as [`Fjall::open`] does.
    #[doc(hidden)]
    pub fn open_tuned(path: impl AsRef<Path>, tuning: Tuning) -> Result<Self> {
        if path.as_ref().exists() {
            clear_unfinished(path.as_ref())?;
            sync_journals(path.as_ref())?;
        }
        let db = Database::builder(path.as_ref())
            .cache_size(tuning.cache_bytes)
            .open()?;
        let store = Self(Arc::new(Partitions {
            state: db.keyspace("state", || tuning.rows())?,
            // System keys are looked up for session indexes and replies
            // that are often absent: keep the filters that answer misses
            // cheaply.
            system: db.keyspace("system", KeyspaceCreateOptions::default)?,
            log: db.keyspace("log", KeyspaceCreateOptions::default)?,
            blobs: db.keyspace("blobs", KeyspaceCreateOptions::default)?,
            db,
        }));
        store.check_layout()?;
        Ok(store)
    }

    /// Check the store's layout row against [`LAYOUT`], writing it, synced,
    /// to a store that holds no rows yet. A store whose rows were written
    /// under another layout, or that holds rows and names no layout (it
    /// was written before layouts were numbered), is refused with a
    /// [`LayoutMismatch`] rather than read as if its rows were where this
    /// build looks for them.
    fn check_layout(&self) -> Result<()> {
        let key = node_record(NodeRow::Layout, &[]);
        let found = match self.system().get(&key)? {
            Some(value) => Some(
                <[u8; 4]>::try_from(&value[..])
                    .map(u32::from_be_bytes)
                    .map_err(|_| LayoutMismatch::refuse(Layout::Unreadable))?,
            ),
            None => None,
        };
        match found {
            Some(LAYOUT) => Ok(()),
            Some(layout) => Err(LayoutMismatch::refuse(Layout::Other(layout))),
            None if self.holds_nothing()? => {
                self.system().insert(key, LAYOUT.to_be_bytes())?;
                self.database().persist(PersistMode::SyncAll)
            }
            None => Err(LayoutMismatch::refuse(Layout::Unnamed)),
        }
    }

    fn holds_nothing(&self) -> Result<bool> {
        for partition in [self.state(), self.system(), self.log(), self.blobs()] {
            if !partition.is_empty()? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// What a refused store's layout row says.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Layout {
    /// A layout other than [`LAYOUT`].
    Other(u32),
    /// No layout row, in a store that holds rows.
    Unnamed,
    /// A layout row that is not a number.
    Unreadable,
}

/// A store refused at open: its rows are laid out other than this build
/// reads them. It reaches the caller as an [`Error::Io`] of kind
/// `InvalidData` carrying this value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LayoutMismatch {
    pub found: Layout,
}

impl LayoutMismatch {
    fn refuse(found: Layout) -> Error {
        Error::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            Self { found },
        ))
    }

    /// The mismatch an open refused with, if that is why it failed.
    pub fn of(error: &Error) -> Option<Self> {
        match error {
            Error::Io(inner) => inner.get_ref()?.downcast_ref::<Self>().copied(),
            _ => None,
        }
    }

    /// `error` as an operator reads it: the mismatch's account when an
    /// open refused the store's layout, its `Debug` otherwise.
    pub fn shown(error: &Error) -> String {
        Self::of(error).map_or_else(|| format!("{error:?}"), |mismatch| mismatch.to_string())
    }
}

impl std::fmt::Display for LayoutMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.found {
            Layout::Other(layout) => write!(
                f,
                "the store is laid out as layout {layout} and this build reads layout {LAYOUT}"
            ),
            Layout::Unnamed => write!(
                f,
                "the store holds rows and names no layout: it was written before \
                 layouts were numbered, and this build reads layout {LAYOUT}"
            ),
            Layout::Unreadable => write!(f, "the store's layout row is unreadable"),
        }?;
        f.write_str(
            "; move the store aside to start a new one, which discards the node's secret, \
             the key its venue lists",
        )
    }
}

impl std::error::Error for LayoutMismatch {}
