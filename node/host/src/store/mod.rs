//! The node's storage: one LSM keyspace with four partitions.
//!
//! - `state`: agents' instance rows, keyed by agent and epoch, then the
//!   agent-relative key;
//! - `system`: agents' system keys (sessions, reply windows, pair marks,
//!   the outbox), keyed the same way, and the node's own rows for each
//!   agent (its applied index, its Raft state), above every epoch;
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
mod keys;
mod read;
#[cfg(test)]
mod tests;

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;

use fjall::{Database, Keyspace, KeyspaceCreateOptions, Readable};
use vos_wire::Decode;
use vos_wire::ids::AgentId;
use vos_wire::peer::{CreationRecord, Placement};

use keys::{
    NODE, NodeRow, SYSTEM, agent_key, be_u64, decode_entry, decode_hard, decode_membership,
    log_index, log_key, node_record, node_row, registry_prefix,
};

pub use batch::Batch;
pub use fjall::{Error, PersistMode};
pub use keys::{NODE_AGENT, decode_configuration, encode_configuration, next_epoch};
pub use read::{Export, Snapshot};

pub type Result<T> = std::result::Result<T, Error>;

/// A node in an agent's replica set: the 8-bit node part of an agent id.
pub type NodeNumber = u8;

/// A work result of this many bytes or more is stored as a blob, which its
/// log entry names: inline, entries this large hold up every agent's small
/// ones behind their writes.
pub const LARGE_RESULT: usize = 64 << 10;

// An append carries entries up to vos-raft's 1 MiB cap, or one larger entry
// alone, and a work result is inline only under `LARGE_RESULT`.
const _: () = assert!(
    vos_net::Limits::DEFAULT.consensus >= (1 << 20) + LARGE_RESULT + (64 << 10),
    "a consensus frame must hold an append"
);

/// What a log entry holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum EntryKind {
    /// A new leader's first entry in its term.
    NoOp = 0,
    /// A work result.
    Result = 1,
    /// A change to the agent's replica set.
    Configuration = 2,
    /// A work result of [`LARGE_RESULT`] bytes or more: the entry's first
    /// blob, its body empty.
    LargeResult = 3,
}

impl EntryKind {
    fn from_u8(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::NoOp,
            1 => Self::Result,
            2 => Self::Configuration,
            3 => Self::LargeResult,
            _ => return None,
        })
    }
}

/// A blob an entry depends on: a large work result, or a program it
/// installs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BlobRef {
    pub hash: [u8; 32],
    pub len: u64,
}

/// One log entry: what it holds, the term it was proposed in, and the
/// blobs it depends on, which the store reads without decoding the body.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LogEntry {
    pub term: u64,
    pub kind: EntryKind,
    pub blobs: Vec<BlobRef>,
    pub body: Vec<u8>,
}

impl LogEntry {
    /// A work result held inline.
    pub fn result(term: u64, body: Vec<u8>) -> Self {
        Self {
            term,
            kind: EntryKind::Result,
            blobs: Vec::new(),
            body,
        }
    }

    /// The blob holding a large work result, if the entry is one.
    pub fn result_blob(&self) -> Option<&BlobRef> {
        match self.kind {
            EntryKind::LargeResult => self.blobs.first(),
            _ => None,
        }
    }

    /// The entry without its term: its kind, its blobs and its body, as a
    /// Raft data entry carries it.
    pub fn payload(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(3 + self.blobs.len() * 40 + self.body.len());
        out.push(self.kind as u8);
        let count = u16::try_from(self.blobs.len()).expect("at most 65,535 blobs per entry");
        out.extend_from_slice(&count.to_be_bytes());
        for blob in &self.blobs {
            out.extend_from_slice(&blob.hash);
            out.extend_from_slice(&blob.len.to_be_bytes());
        }
        out.extend_from_slice(&self.body);
        out
    }

    /// The length of the large work result `payload` names, if its entry
    /// is one, read without copying the body.
    pub fn result_len(payload: &[u8]) -> Option<u64> {
        let (&kind, rest) = payload.split_first()?;
        let (count, rest) = rest.split_first_chunk::<2>()?;
        if kind != EntryKind::LargeResult as u8 || *count == [0; 2] {
            return None;
        }
        let len = rest.get(32..40)?;
        Some(u64::from_be_bytes(len.try_into().expect("8 bytes")))
    }

    /// The entry at `term` whose payload is `payload`.
    pub fn from_payload(term: u64, payload: &[u8]) -> Option<Self> {
        let (&kind, rest) = payload.split_first()?;
        let kind = EntryKind::from_u8(kind)?;
        let (count, mut rest) = rest.split_first_chunk::<2>()?;
        let mut blobs = Vec::with_capacity(usize::from(u16::from_be_bytes(*count)));
        for _ in 0..u16::from_be_bytes(*count) {
            let (hash, after) = rest.split_first_chunk::<32>()?;
            let (len, after) = after.split_first_chunk::<8>()?;
            blobs.push(BlobRef {
                hash: *hash,
                len: u64::from_be_bytes(*len),
            });
            rest = after;
        }
        Some(Self {
            term,
            kind,
            blobs,
            body: rest.to_vec(),
        })
    }
}

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

    /// The agent's stored log indices from `from` on, in order.
    fn log_indices(&self, agent: AgentId, from: u64) -> impl Iterator<Item = Result<u64>> + '_ {
        let prefix = agent.0.to_be_bytes();
        self.log()
            .range(log_key(agent, from)..)
            .map(|row| row.key())
            .take_while(move |key| match key {
                Ok(key) => key.starts_with(&prefix),
                Err(_) => true,
            })
            .map(|key| Ok(log_index(&key?).expect("an 8-byte log index")))
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
        let row = |kind| self.system().get(node_row(agent, kind, &[]));
        Ok(AgentRows {
            epoch: row(NodeRow::Epoch)?
                .and_then(|bytes| bytes.first().copied())
                .unwrap_or(0),
            applied: row(NodeRow::Applied)?
                .and_then(|bytes| be_u64(&bytes))
                .unwrap_or(0),
            log_start: row(NodeRow::LogStart)?
                .and_then(|bytes| be_u64(bytes.get(..8)?))
                .unwrap_or(0),
        })
    }

    pub(crate) fn database(&self) -> &Database {
        &self.0.db
    }

    /// The blob store's partition.
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
            let value = row.value()?;
            let entry = decode_entry(&value).expect("a log entry this store wrote");
            referenced.extend(entry.blobs.iter().map(|blob| blob.hash));
        }
        for row in snapshot.prefix(self.blobs(), [crate::blobs::IndexRow::Pin as u8]) {
            let key = row.key()?;
            referenced.insert(key[1..33].try_into().expect("a pin names a hash"));
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
        let hard = self
            .system()
            .get(node_row(agent, NodeRow::Hard, &[]))?
            .and_then(|bytes| decode_hard(&bytes))
            .unwrap_or_default();
        let start_row = self.system().get(node_row(agent, NodeRow::LogStart, &[]))?;
        let log_start = start_row
            .as_ref()
            .and_then(|bytes| Some((be_u64(bytes.get(..8)?)?, be_u64(bytes.get(8..16)?)?)))
            .unwrap_or((0, 0));
        let log_start_membership = start_row
            .as_ref()
            .and_then(|bytes| decode_membership(bytes.get(16..)?));
        let membership = self
            .system()
            .get(node_row(agent, NodeRow::Membership, &[]))?
            .and_then(|bytes| decode_membership(&bytes));
        let applied = self
            .system()
            .get(node_row(agent, NodeRow::Applied, &[]))?
            .and_then(|bytes| be_u64(&bytes))
            .unwrap_or(0);
        let log = self.log_range(agent, log_start.0 + 1, u64::MAX, usize::MAX)?;
        let vote_floor = self
            .system()
            .get(node_row(agent, NodeRow::VoteFloor, &[]))?
            .and_then(|bytes| Some((be_u64(bytes.get(..8)?)?, be_u64(bytes.get(8..16)?)?)));
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
        let current = self
            .system()
            .get(node_row(agent, NodeRow::Epoch, &[]))?
            .and_then(|bytes| bytes.first().copied())
            .unwrap_or(0);
        let mut stale = Vec::new();
        for epoch in 0..NODE {
            if epoch == current {
                continue;
            }
            let prefix = agent_key(agent, epoch, &[]);
            if self.system().prefix(&prefix).next().is_some()
                || self.state().prefix(&prefix).next().is_some()
            {
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
            match CreationRecord::decode(&value) {
                Ok((record, used)) if used == value.len() => records.push(record),
                _ => tracing::error!(
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
            let placement = match Placement::decode(&value) {
                Ok((placement, used)) if used == value.len() => Some(placement),
                _ => None,
            };
            placements.insert(agent, placement);
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

// The store benchmark's tuning and probes: not the node's API.

/// Read tuning for the `state` partition. The defaults are the fastest
/// configuration the store benchmark found at 10M rows.
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct Tuning {
    /// Block cache, shared by every partition.
    pub cache_bytes: u64,
    /// Skip filters on the last level, where most rows live: reads of
    /// actor state mostly hit, and a filter that says "maybe" costs a
    /// lookup for nothing. Misses then cost a block search.
    pub expect_hits: bool,
    /// Size of the hash index in each data block, relative to its keys; 0
    /// builds none, and a point read binary-searches the block.
    pub hash_ratio: f32,
    /// Keep every level's filter and index blocks in the cache.
    pub pin_all: bool,
}

impl Default for Tuning {
    fn default() -> Self {
        Self {
            cache_bytes: 1 << 30,
            expect_hits: true,
            hash_ratio: 0.0,
            pin_all: false,
        }
    }
}

impl Tuning {
    fn rows(&self) -> KeyspaceCreateOptions {
        use fjall::config::{HashRatioPolicy, PinningPolicy};
        let mut options = KeyspaceCreateOptions::default()
            .expect_point_read_hits(self.expect_hits)
            .data_block_hash_ratio_policy(HashRatioPolicy::all(self.hash_ratio));
        if self.pin_all {
            options = options
                .filter_block_pinning_policy(PinningPolicy::all(true))
                .index_block_pinning_policy(PinningPolicy::all(true));
        }
        options
    }
}

impl Fjall {
    /// Open the store at `path` with `tuning`, as [`Fjall::open`] does.
    #[doc(hidden)]
    pub fn open_tuned(path: impl AsRef<Path>, tuning: Tuning) -> Result<Self> {
        if path.as_ref().exists() {
            sync_journals(path.as_ref())?;
        }
        let db = Database::builder(path.as_ref())
            .cache_size(tuning.cache_bytes)
            .open()?;
        Ok(Self(Arc::new(Partitions {
            state: db.keyspace("state", || tuning.rows())?,
            // System keys are looked up for session indexes and replies
            // that are often absent: keep the filters that answer misses
            // cheaply.
            system: db.keyspace("system", KeyspaceCreateOptions::default)?,
            log: db.keyspace("log", KeyspaceCreateOptions::default)?,
            blobs: db.keyspace("blobs", KeyspaceCreateOptions::default)?,
            db,
        })))
    }

    /// Compact the state partitions into one sorted run each, as after a
    /// bulk load.
    #[doc(hidden)]
    pub fn compact(&self) -> Result<()> {
        self.state().major_compact()?;
        self.system().major_compact()?;
        Ok(())
    }

    #[doc(hidden)]
    pub fn disk_space(&self) -> Result<u64> {
        self.database().disk_space()
    }

    /// The bytes of the state partition's active memtable, which a read
    /// of its rows searches first: it only grows until the memtable is
    /// sealed and another takes its place.
    #[doc(hidden)]
    pub fn state_memtable_bytes(&self) -> u64 {
        use fjall::AbstractTree;
        self.state().tree.active_memtable().size()
    }

    /// The state partition's sealed memtables not yet flushed, which reads
    /// search next.
    #[doc(hidden)]
    pub fn state_sealed_memtables(&self) -> usize {
        self.state().sealed_memtable_count()
    }
}
