//! The node's storage: one LSM keyspace with four partitions.
//!
//! - `state`: agents' instance rows, keyed by agent and epoch, then the
//!   agent-relative key;
//! - `system`: agents' system keys (sessions, reply windows, pair marks,
//!   the outbox), keyed the same way, and the node's own rows for each
//!   agent (its applied index, its Raft state), above every epoch;
//! - `log`: each agent's log, by (agent, index);
//! - `programs`: program blobs by hash.
//!
//! An agent's rows live under an epoch, so that a snapshot can be installed
//! beside the current state and switched to at once; every agent is at
//! epoch 0 until snapshots arrive.
//!
//! Writes go through a [`Batch`]; the storage thread groups several agents'
//! batches into one commit. A replicated agent appends with a sync before
//! applying, and applies without one (section 9.5).

use std::collections::HashMap;
use std::ops::Bound;
use std::path::Path;

use fjall::{Database, Keyspace, KeyspaceCreateOptions, PersistMode, Readable};
use vos_wire::ids::{AgentId, ProgramHash, SessionId};
use vos_wire::result::Write;

pub use fjall::Error;

pub type Result<T> = std::result::Result<T, Error>;

/// A node in an agent's replica set: the 8-bit node part of an agent id.
pub type NodeNumber = u8;

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
}

impl EntryKind {
    fn from_u8(byte: u8) -> Option<Self> {
        Some(match byte {
            0 => Self::NoOp,
            1 => Self::Result,
            2 => Self::Configuration,
            _ => return None,
        })
    }
}

/// A blob an entry depends on: a work result too large to inline, or a
/// program it installs.
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
}

/// Whether a commit returns before or after its data reaches the disk.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Durability {
    /// Handed to the operating system: survives a process crash, not a
    /// power loss.
    Buffered,
    /// Synced to the disk.
    Synced,
}

/// The node's storage.
pub trait Store: Send + Sync {
    type Snapshot: View;
    type Batch: Batch;

    /// A consistent view of every agent's applied state, for refines and
    /// queries.
    fn snapshot(&self) -> Self::Snapshot;

    fn batch(&self) -> Self::Batch;

    fn log_entry(&self, agent: AgentId, index: u64) -> Result<Option<LogEntry>>;

    /// Entries `from..=to`, in order, within `max_bytes` but at least one
    /// when any is stored.
    fn log_range(
        &self,
        agent: AgentId,
        from: u64,
        to: u64,
        max_bytes: usize,
    ) -> Result<Vec<(u64, LogEntry)>>;

    /// The agent's Raft state, for recovery.
    fn raft(&self, agent: AgentId) -> Result<RaftRows>;

    fn program(&self, hash: &ProgramHash) -> Result<Option<Vec<u8>>>;

    /// Every stored program, for the machine pool at start.
    fn programs(&self) -> Result<Vec<(ProgramHash, Vec<u8>)>>;

    /// The agents this node runs, each with its agent program.
    fn agents(&self) -> Result<Vec<(AgentId, ProgramHash)>>;

    /// The node's identity, once made.
    fn node_id(&self) -> Result<Option<[u8; 32]>>;

    /// The sessions the node knows, each with its client's key.
    fn sessions(&self) -> Result<Vec<(SessionId, [u8; 32])>>;

    /// The id the next session gets: ids are never reused.
    fn next_session(&self) -> Result<u64>;

    /// When `key` last opened a session, by its own clock.
    fn key_opened(&self, key: &[u8; 32]) -> Result<Option<u64>>;
}

/// A read-only view of applied state. Keys are relative to the agent.
pub trait View: Send + Sync {
    fn get(&self, agent: AgentId, key: &[u8]) -> Result<Option<Vec<u8>>>;

    /// Rows whose key starts with `prefix`, in key order, starting after
    /// `after` when given. `prefix` must not be empty: it selects the
    /// partition.
    fn scan(
        &self,
        agent: AgentId,
        prefix: &[u8],
        after: Option<&[u8]>,
    ) -> impl Iterator<Item = Result<(Vec<u8>, Vec<u8>)>>;

    /// The last log index applied to the agent's state.
    fn applied(&self, agent: AgentId) -> Result<Option<u64>>;
}

/// An atomic group of writes: all of them or none survive a crash.
pub trait Batch {
    fn append(&mut self, agent: AgentId, index: u64, entry: &LogEntry);

    /// Remove the agent's log entries after `after`, including any this
    /// batch appended.
    fn truncate(&mut self, agent: AgentId, after: u64);

    /// Remove the agent's log entries through `through`, whose term is
    /// `term`, and start the log after it, with `membership` the replica
    /// set in effect there, when known.
    fn compact(&mut self, agent: AgentId, through: u64, term: u64, membership: Option<&Membership>);

    fn hard_state(&mut self, agent: AgentId, hard: &HardState);

    fn membership(&mut self, agent: AgentId, membership: &Membership);

    /// Apply a work result's writes, in order, and record `index` as the
    /// agent's applied index.
    fn apply<'a>(
        &mut self,
        agent: AgentId,
        index: u64,
        writes: impl IntoIterator<Item = &'a Write>,
    );

    fn program(&mut self, hash: &ProgramHash, blob: &[u8]);

    /// Record that this node runs `agent` with the agent program `program`.
    fn agent(&mut self, agent: AgentId, program: &ProgramHash);

    fn node_id(&mut self, id: &[u8; 32]);

    /// Record session `id` for `key`, opened at `time`, and that the next
    /// session gets `id + 1`.
    fn session(&mut self, id: SessionId, key: &[u8; 32], time: u64);

    fn forget_session(&mut self, id: SessionId);

    fn commit(self, durability: Durability) -> Result<()>;
}

/// The first byte of an agent-relative system key ([`vos_wire::keys`]).
const SYSTEM: u8 = 0x00;
/// The epoch every agent's rows are under, until snapshots switch epochs.
const EPOCH: u8 = 0x00;
/// After an agent id, the node's own rows for the agent: above every
/// epoch, so no agent row reaches them.
const NODE: u8 = 0xff;
/// The id no agent gets: node-wide records live under its node rows.
pub const NODE_AGENT: AgentId = AgentId(u32::MAX);

/// The node's rows, under an agent's id (or [`NODE_AGENT`]'s).
#[derive(Clone, Copy)]
#[repr(u8)]
enum NodeRow {
    Applied = 0x00,
    Agent = 0x01,
    NodeId = 0x02,
    Session = 0x03,
    NextSession = 0x04,
    KeyOpened = 0x05,
    Hard = 0x06,
    LogStart = 0x07,
    Membership = 0x08,
}

fn agent_key(agent: AgentId, key: &[u8]) -> Vec<u8> {
    [&agent.0.to_be_bytes()[..], &[EPOCH], key].concat()
}

/// The bytes before an agent's relative keys.
const AGENT_KEY_PREFIX: usize = 5;

fn node_row(agent: AgentId, row: NodeRow, rest: &[u8]) -> Vec<u8> {
    [&agent.0.to_be_bytes()[..], &[NODE, row as u8], rest].concat()
}

fn registry_prefix() -> Vec<u8> {
    node_row(NODE_AGENT, NodeRow::Agent, &[])
}

/// A node-wide record: under the node's reserved agent id.
fn node_record(row: NodeRow, rest: &[u8]) -> Vec<u8> {
    node_row(NODE_AGENT, row, rest)
}

fn be_u64(bytes: &[u8]) -> Option<u64> {
    Some(u64::from_be_bytes(bytes.try_into().ok()?))
}

fn log_key(agent: AgentId, index: u64) -> Vec<u8> {
    [&agent.0.to_be_bytes()[..], &index.to_be_bytes()].concat()
}

fn log_index(key: &[u8]) -> Option<u64> {
    be_u64(key.get(4..)?)
}

fn encode_entry(entry: &LogEntry) -> Vec<u8> {
    [&entry.term.to_be_bytes()[..], &entry.payload()].concat()
}

fn decode_entry(bytes: &[u8]) -> Option<LogEntry> {
    let (term, payload) = bytes.split_first_chunk::<8>()?;
    LogEntry::from_payload(u64::from_be_bytes(*term), payload)
}

fn encode_hard(hard: &HardState) -> Vec<u8> {
    let mut out = hard.term.to_be_bytes().to_vec();
    match hard.vote {
        Some(vote) => out.extend_from_slice(&[1, vote]),
        None => out.extend_from_slice(&[0, 0]),
    }
    out.extend_from_slice(&hard.commit.to_be_bytes());
    out
}

fn decode_hard(bytes: &[u8]) -> Option<HardState> {
    let (term, rest) = bytes.split_first_chunk::<8>()?;
    let (vote, rest) = rest.split_first_chunk::<2>()?;
    Some(HardState {
        term: u64::from_be_bytes(*term),
        vote: (vote[0] == 1).then_some(vote[1]),
        commit: be_u64(rest)?,
    })
}

fn encode_nodes(out: &mut Vec<u8>, nodes: &[NodeNumber]) {
    out.push(u8::try_from(nodes.len()).expect("at most 255 replicas"));
    out.extend_from_slice(nodes);
}

fn decode_nodes(bytes: &[u8]) -> Option<(Vec<NodeNumber>, &[u8])> {
    let (&count, rest) = bytes.split_first()?;
    let (nodes, rest) = rest.split_at_checked(usize::from(count))?;
    Some((nodes.to_vec(), rest))
}

fn encode_membership(membership: &Membership) -> Vec<u8> {
    let mut out = Vec::new();
    match membership.index {
        Some(index) => {
            out.push(1);
            out.extend_from_slice(&index.to_be_bytes());
        }
        None => out.push(0),
    }
    encode_nodes(&mut out, &membership.members);
    match &membership.joint_old {
        Some(old) => {
            out.push(1);
            encode_nodes(&mut out, old);
        }
        None => out.push(0),
    }
    out
}

fn decode_membership(bytes: &[u8]) -> Option<Membership> {
    let (&has_index, mut rest) = bytes.split_first()?;
    let index = if has_index == 1 {
        let (index, after) = rest.split_first_chunk::<8>()?;
        rest = after;
        Some(u64::from_be_bytes(*index))
    } else {
        None
    };
    let (members, rest) = decode_nodes(rest)?;
    let (&has_old, rest) = rest.split_first()?;
    let joint_old = if has_old == 1 {
        Some(decode_nodes(rest)?.0)
    } else {
        None
    };
    Some(Membership {
        index,
        members,
        joint_old,
    })
}

/// A configuration entry's body: the replica set, and the old one while
/// joint.
pub fn encode_configuration(members: &[NodeNumber], joint_old: Option<&[NodeNumber]>) -> Vec<u8> {
    let mut out = Vec::new();
    encode_nodes(&mut out, members);
    match joint_old {
        Some(old) => {
            out.push(1);
            encode_nodes(&mut out, old);
        }
        None => out.push(0),
    }
    out
}

/// The replica set, and the old one while joint, from a configuration
/// entry's body.
pub fn decode_configuration(body: &[u8]) -> Option<(Vec<NodeNumber>, Option<Vec<NodeNumber>>)> {
    let (members, rest) = decode_nodes(body)?;
    let (&has_old, rest) = rest.split_first()?;
    let joint_old = if has_old == 1 {
        Some(decode_nodes(rest)?.0)
    } else {
        None
    };
    Some((members, joint_old))
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

/// Read tuning for the `state` partition. The defaults are the fastest
/// configuration the store benchmark found at 10M rows.
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

/// The fjall-backed store.
#[derive(Clone)]
pub struct Fjall {
    db: Database,
    state: Keyspace,
    system: Keyspace,
    log: Keyspace,
    programs: Keyspace,
}

impl Fjall {
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        Self::open_tuned(path, Tuning::default())
    }

    /// Open the store at `path`. Everything it will recover is synced
    /// first: rows a crashed process left in the page cache could otherwise
    /// still be lost to a power cut after the node relied on them. (This
    /// rests on fjall 3.1's files: it syncs its tables and a journal before
    /// rotating it, so only journals can hold unsynced rows. Re-check it on
    /// an upgrade.)
    pub fn open_tuned(path: impl AsRef<Path>, tuning: Tuning) -> Result<Self> {
        if path.as_ref().exists() {
            sync_journals(path.as_ref())?;
        }
        let db = Database::builder(path.as_ref())
            .cache_size(tuning.cache_bytes)
            .open()?;
        Ok(Self {
            state: db.keyspace("state", || tuning.rows())?,
            // System keys are looked up for sessions and replies that are
            // often absent: keep the filters that answer misses cheaply.
            system: db.keyspace("system", KeyspaceCreateOptions::default)?,
            log: db.keyspace("log", KeyspaceCreateOptions::default)?,
            programs: db.keyspace("programs", KeyspaceCreateOptions::default)?,
            db,
        })
    }

    fn partition(&self, key: &[u8]) -> &Keyspace {
        match key.first() {
            Some(&SYSTEM) => &self.system,
            _ => &self.state,
        }
    }

    /// The agent's stored log indices from `from` on, in order.
    fn log_indices(&self, agent: AgentId, from: u64) -> impl Iterator<Item = Result<u64>> + '_ {
        let prefix = agent.0.to_be_bytes();
        self.log
            .range(log_key(agent, from)..)
            .map(|row| row.key())
            .take_while(move |key| match key {
                Ok(key) => key.starts_with(&prefix),
                Err(_) => true,
            })
            .map(|key| Ok(log_index(&key?).expect("an 8-byte log index")))
    }

    fn last_log_index(&self, agent: AgentId) -> Result<Option<u64>> {
        let prefix = agent.0.to_be_bytes();
        match self.log.prefix(prefix).next_back() {
            Some(row) => Ok(log_index(&row.key()?)),
            None => Ok(None),
        }
    }

    /// Compact the state partitions into one sorted run each, as after a
    /// bulk load.
    pub fn compact(&self) -> Result<()> {
        self.state.major_compact()?;
        self.system.major_compact()?;
        Ok(())
    }

    pub fn disk_space(&self) -> Result<u64> {
        self.db.disk_space()
    }
}

impl Store for Fjall {
    type Snapshot = FjallSnapshot;
    type Batch = FjallBatch;

    fn snapshot(&self) -> FjallSnapshot {
        FjallSnapshot {
            snapshot: self.db.snapshot(),
            store: self.clone(),
        }
    }

    fn batch(&self) -> FjallBatch {
        FjallBatch {
            batch: self.db.batch(),
            store: self.clone(),
            appended: HashMap::new(),
            error: None,
        }
    }

    fn log_entry(&self, agent: AgentId, index: u64) -> Result<Option<LogEntry>> {
        Ok(self
            .log
            .get(log_key(agent, index))?
            .map(|bytes| decode_entry(&bytes).expect("a log entry this store wrote")))
    }

    fn log_range(
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
        for row in self.log.range(log_key(agent, from)..=log_key(agent, to)) {
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

    fn raft(&self, agent: AgentId) -> Result<RaftRows> {
        let hard = self
            .system
            .get(node_row(agent, NodeRow::Hard, &[]))?
            .and_then(|bytes| decode_hard(&bytes))
            .unwrap_or_default();
        let start_row = self.system.get(node_row(agent, NodeRow::LogStart, &[]))?;
        let log_start = start_row
            .as_ref()
            .and_then(|bytes| Some((be_u64(bytes.get(..8)?)?, be_u64(bytes.get(8..16)?)?)))
            .unwrap_or((0, 0));
        let log_start_membership = start_row
            .as_ref()
            .and_then(|bytes| decode_membership(bytes.get(16..)?));
        let membership = self
            .system
            .get(node_row(agent, NodeRow::Membership, &[]))?
            .and_then(|bytes| decode_membership(&bytes));
        let applied = self
            .system
            .get(node_row(agent, NodeRow::Applied, &[]))?
            .and_then(|bytes| be_u64(&bytes))
            .unwrap_or(0);
        let log = self.log_range(agent, log_start.0 + 1, u64::MAX, usize::MAX)?;
        Ok(RaftRows {
            hard,
            log_start,
            log_start_membership,
            membership,
            applied,
            log,
        })
    }

    fn program(&self, hash: &ProgramHash) -> Result<Option<Vec<u8>>> {
        Ok(self.programs.get(hash.0)?.map(|blob| blob.to_vec()))
    }

    fn programs(&self) -> Result<Vec<(ProgramHash, Vec<u8>)>> {
        self.programs
            .iter()
            .map(|row| {
                let (hash, blob) = row.into_inner()?;
                let hash = hash[..].try_into().expect("a 32-byte program hash");
                Ok((ProgramHash(hash), blob.to_vec()))
            })
            .collect()
    }

    fn node_id(&self) -> Result<Option<[u8; 32]>> {
        Ok(self
            .system
            .get(node_record(NodeRow::NodeId, &[]))?
            .and_then(|id| id[..].try_into().ok()))
    }

    fn sessions(&self) -> Result<Vec<(SessionId, [u8; 32])>> {
        let prefix = node_record(NodeRow::Session, &[]);
        self.system
            .prefix(&prefix)
            .filter_map(|row| {
                let (key, value) = match row.into_inner() {
                    Ok(row) => row,
                    Err(error) => return Some(Err(error)),
                };
                // A record this node did not write is skipped, not trusted.
                let id = be_u64(&key[prefix.len()..])?;
                let client = value.get(..32)?.try_into().ok()?;
                Some(Ok((SessionId(id), client)))
            })
            .collect()
    }

    fn next_session(&self) -> Result<u64> {
        Ok(self
            .system
            .get(node_record(NodeRow::NextSession, &[]))?
            .and_then(|next| be_u64(&next))
            .unwrap_or(1))
    }

    fn key_opened(&self, key: &[u8; 32]) -> Result<Option<u64>> {
        Ok(self
            .system
            .get(node_record(NodeRow::KeyOpened, key))?
            .and_then(|time| be_u64(&time)))
    }

    fn agents(&self) -> Result<Vec<(AgentId, ProgramHash)>> {
        let prefix = registry_prefix();
        self.system
            .prefix(&prefix)
            .map(|row| {
                let (key, program) = row.into_inner()?;
                let agent = key[prefix.len()..].try_into().expect("an agent id");
                let program = program[..].try_into().expect("a program hash");
                Ok((AgentId(u32::from_be_bytes(agent)), ProgramHash(program)))
            })
            .collect()
    }
}

pub struct FjallSnapshot {
    snapshot: fjall::Snapshot,
    store: Fjall,
}

impl View for FjallSnapshot {
    fn get(&self, agent: AgentId, key: &[u8]) -> Result<Option<Vec<u8>>> {
        Ok(self
            .snapshot
            .get(self.store.partition(key), agent_key(agent, key))?
            .map(|value| value.to_vec()))
    }

    fn scan(
        &self,
        agent: AgentId,
        prefix: &[u8],
        after: Option<&[u8]>,
    ) -> impl Iterator<Item = Result<(Vec<u8>, Vec<u8>)>> {
        assert!(!prefix.is_empty(), "a scan names its partition");
        let start = match after {
            Some(after) if after >= prefix => Bound::Excluded(agent_key(agent, after)),
            _ => Bound::Included(agent_key(agent, prefix)),
        };
        let prefix = agent_key(agent, prefix);
        self.snapshot
            .range(
                self.store.partition(&prefix[AGENT_KEY_PREFIX..]),
                (start, Bound::Unbounded),
            )
            .map(|row| row.into_inner())
            .take_while(move |row| match row {
                Ok((key, _)) => key.starts_with(&prefix),
                Err(_) => true,
            })
            .map(|row| {
                let (key, value) = row?;
                Ok((key[AGENT_KEY_PREFIX..].to_vec(), value.to_vec()))
            })
    }

    fn applied(&self, agent: AgentId) -> Result<Option<u64>> {
        Ok(self
            .snapshot
            .get(&self.store.system, node_row(agent, NodeRow::Applied, &[]))?
            .and_then(|bytes| be_u64(&bytes)))
    }
}

pub struct FjallBatch {
    batch: fjall::OwnedWriteBatch,
    store: Fjall,
    /// The highest index this batch appended, per agent: a truncation
    /// later in the batch removes those too.
    appended: HashMap<AgentId, u64>,
    /// A read the batch needed failed: it then commits nothing.
    error: Option<Error>,
}

impl Batch for FjallBatch {
    fn append(&mut self, agent: AgentId, index: u64, entry: &LogEntry) {
        self.batch
            .insert(&self.store.log, log_key(agent, index), encode_entry(entry));
        let last = self.appended.entry(agent).or_insert(index);
        *last = (*last).max(index);
    }

    fn truncate(&mut self, agent: AgentId, after: u64) {
        let stored = match self.store.last_log_index(agent) {
            Ok(stored) => stored,
            Err(error) => {
                self.error.get_or_insert(error);
                return;
            }
        };
        let appended = self.appended.get(&agent).copied();
        let last = stored.max(appended).unwrap_or(0);
        for index in after.saturating_add(1)..=last {
            self.batch.remove(&self.store.log, log_key(agent, index));
        }
        if let Some(appended) = self.appended.get_mut(&agent) {
            *appended = (*appended).min(after);
        }
    }

    fn compact(
        &mut self,
        agent: AgentId,
        through: u64,
        term: u64,
        membership: Option<&Membership>,
    ) {
        let mut stored = Vec::new();
        for index in self.store.log_indices(agent, 0) {
            match index {
                Ok(index) if index <= through => stored.push(index),
                Ok(_) => break,
                Err(error) => {
                    self.error.get_or_insert(error);
                    return;
                }
            }
        }
        for index in stored {
            self.batch.remove(&self.store.log, log_key(agent, index));
        }
        let start = [
            &through.to_be_bytes()[..],
            &term.to_be_bytes(),
            &membership.map(encode_membership).unwrap_or_default(),
        ]
        .concat();
        self.batch.insert(
            &self.store.system,
            node_row(agent, NodeRow::LogStart, &[]),
            start,
        );
    }

    fn hard_state(&mut self, agent: AgentId, hard: &HardState) {
        self.batch.insert(
            &self.store.system,
            node_row(agent, NodeRow::Hard, &[]),
            encode_hard(hard),
        );
    }

    fn membership(&mut self, agent: AgentId, membership: &Membership) {
        self.batch.insert(
            &self.store.system,
            node_row(agent, NodeRow::Membership, &[]),
            encode_membership(membership),
        );
    }

    fn apply<'a>(
        &mut self,
        agent: AgentId,
        index: u64,
        writes: impl IntoIterator<Item = &'a Write>,
    ) {
        for write in writes {
            let partition = self.store.partition(&write.key);
            let key = agent_key(agent, &write.key);
            match &write.value {
                Some(value) => self.batch.insert(partition, key, value.as_slice()),
                None => self.batch.remove(partition, key),
            }
        }
        self.batch.insert(
            &self.store.system,
            node_row(agent, NodeRow::Applied, &[]),
            index.to_be_bytes(),
        );
    }

    fn program(&mut self, hash: &ProgramHash, blob: &[u8]) {
        self.batch.insert(&self.store.programs, hash.0, blob);
    }

    fn agent(&mut self, agent: AgentId, program: &ProgramHash) {
        let key = [registry_prefix(), agent.0.to_be_bytes().to_vec()].concat();
        self.batch.insert(&self.store.system, key, program.0);
    }

    fn node_id(&mut self, id: &[u8; 32]) {
        self.batch
            .insert(&self.store.system, node_record(NodeRow::NodeId, &[]), id);
    }

    fn session(&mut self, id: SessionId, key: &[u8; 32], time: u64) {
        let system = &self.store.system;
        let value = [&key[..], &time.to_be_bytes()].concat();
        self.batch.insert(
            system,
            node_record(NodeRow::Session, &id.0.to_be_bytes()),
            value,
        );
        self.batch.insert(
            system,
            node_record(NodeRow::NextSession, &[]),
            (id.0 + 1).to_be_bytes(),
        );
        self.batch.insert(
            system,
            node_record(NodeRow::KeyOpened, key),
            time.to_be_bytes(),
        );
    }

    fn forget_session(&mut self, id: SessionId) {
        self.batch.remove(
            &self.store.system,
            node_record(NodeRow::Session, &id.0.to_be_bytes()),
        );
    }

    fn commit(self, durability: Durability) -> Result<()> {
        if let Some(error) = self.error {
            return Err(error);
        }
        let mode = match durability {
            Durability::Buffered => PersistMode::Buffer,
            Durability::Synced => PersistMode::SyncAll,
        };
        self.batch.durability(Some(mode)).commit()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use vos_wire::ids::{InstanceId, SessionId};
    use vos_wire::keys;

    const A: AgentId = AgentId(1);
    const B: AgentId = AgentId(2);

    fn put(key: Vec<u8>, value: &[u8]) -> Write {
        Write {
            key,
            value: Some(value.to_vec()),
        }
    }

    fn row(instance: u32, index: u64) -> Vec<u8> {
        [
            keys::table_prefix(InstanceId(instance), 7),
            index.to_be_bytes().to_vec(),
        ]
        .concat()
    }

    fn rows(view: &impl View, agent: AgentId, prefix: &[u8], after: Option<&[u8]>) -> Vec<Vec<u8>> {
        view.scan(agent, prefix, after)
            .map(|row| row.unwrap().0)
            .collect()
    }

    #[test]
    fn applies_writes_per_agent_with_their_applied_index() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path()).unwrap();
        let session = keys::session(SessionId(9));
        let mut batch = store.batch();
        batch.apply(
            A,
            1,
            &[put(row(0, 1), b"one"), put(session.clone(), b"mark")],
        );
        batch.apply(B, 4, &[put(row(0, 1), b"other")]);
        batch.commit(Durability::Synced).unwrap();

        let view = store.snapshot();
        assert_eq!(
            view.get(A, &row(0, 1)).unwrap().as_deref(),
            Some(&b"one"[..])
        );
        assert_eq!(
            view.get(B, &row(0, 1)).unwrap().as_deref(),
            Some(&b"other"[..])
        );
        assert_eq!(
            view.get(A, &session).unwrap().as_deref(),
            Some(&b"mark"[..])
        );
        assert_eq!(view.get(B, &session).unwrap(), None);
        assert_eq!(view.applied(A).unwrap(), Some(1));
        assert_eq!(view.applied(B).unwrap(), Some(4));
        assert_eq!(view.applied(AgentId(3)).unwrap(), None);

        let mut batch = store.batch();
        batch.apply(
            A,
            2,
            &[Write {
                key: row(0, 1),
                value: None,
            }],
        );
        batch.commit(Durability::Buffered).unwrap();
        assert_eq!(
            view.get(A, &row(0, 1)).unwrap().as_deref(),
            Some(&b"one"[..]),
            "a snapshot keeps its view"
        );
        assert_eq!(store.snapshot().get(A, &row(0, 1)).unwrap(), None);
        assert_eq!(store.snapshot().applied(A).unwrap(), Some(2));
    }

    #[test]
    fn scans_stay_inside_their_prefix_and_agent() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path()).unwrap();
        let mut batch = store.batch();
        let writes: Vec<_> = (0..5)
            .map(|index| put(row(1, index), b"v"))
            .chain([put(row(0, 9), b"v"), put(row(2, 0), b"v")])
            .collect();
        let mut writes = writes;
        writes.push(put(keys::session(SessionId(1)), b"mark"));
        batch.apply(A, 1, &writes);
        batch.apply(AgentId(0x0100_0000), 1, &[put(row(1, 9), b"v")]);
        batch.apply(B, 1, &[put(row(1, 9), b"v")]);
        batch.commit(Durability::Synced).unwrap();

        let view = store.snapshot();
        let table = keys::table_prefix(InstanceId(1), 7);
        let all: Vec<_> = (0..5).map(|index| row(1, index)).collect();
        assert_eq!(rows(&view, A, &table, None), all);
        assert_eq!(rows(&view, A, &table, Some(&row(1, 2))), all[3..]);
        assert_eq!(
            rows(&view, A, &table, Some(&row(1, 4))),
            Vec::<Vec<u8>>::new()
        );
        assert_eq!(
            rows(&view, A, &table, Some(&row(0, 9))),
            all,
            "a cursor before the prefix starts at the prefix"
        );
        assert_eq!(
            rows(&view, A, &keys::instance_prefix(InstanceId(1)), None),
            all
        );
        assert_eq!(
            rows(&view, A, &[0x00], None),
            vec![keys::session(SessionId(1))],
            "system keys are a partition of their own; the applied index is not an agent key"
        );
        assert_eq!(rows(&view, B, &[0x00], None), Vec::<Vec<u8>>::new());
    }

    #[test]
    fn later_writes_to_a_key_win_within_a_batch() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path()).unwrap();
        let delete = |key: Vec<u8>| Write { key, value: None };
        let mut batch = store.batch();
        batch.apply(
            A,
            1,
            &[
                put(row(0, 1), b"first"),
                put(row(0, 1), b"second"),
                put(row(0, 2), b"gone"),
                delete(row(0, 2)),
                delete(row(0, 3)),
                put(row(0, 3), b"back"),
            ],
        );
        batch.commit(Durability::Buffered).unwrap();
        let view = store.snapshot();
        assert_eq!(
            view.get(A, &row(0, 1)).unwrap().as_deref(),
            Some(&b"second"[..])
        );
        assert_eq!(view.get(A, &row(0, 2)).unwrap(), None);
        assert_eq!(
            view.get(A, &row(0, 3)).unwrap().as_deref(),
            Some(&b"back"[..])
        );
    }

    /// A snapshot sees the applied index and the state rows, which live in
    /// different partitions, as of one commit, while commits continue.
    #[test]
    fn snapshots_agree_across_partitions_under_concurrent_writes() {
        const SLOTS: u64 = 16;
        const RESULTS: u64 = 400;
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path()).unwrap();
        // Work result i writes i into slots i, i + 1 and i + 2 (mod SLOTS):
        // after result n, slot s holds the last i <= n that wrote it.
        let writes = |index: u64| -> Vec<Write> {
            (0..3)
                .map(|k| put(row(0, (index + k) % SLOTS), &index.to_be_bytes()))
                .collect()
        };
        let expected = |applied: u64, slot: u64| -> Option<u64> {
            (1..=applied)
                .rev()
                .find(|index| (0..3).any(|k| (index + k) % SLOTS == slot))
        };
        std::thread::scope(|scope| {
            scope.spawn(|| {
                for index in 1..=RESULTS {
                    let mut batch = store.batch();
                    batch.apply(A, index, &writes(index));
                    batch.commit(Durability::Buffered).unwrap();
                }
            });
            let mut seen = 0;
            while seen < RESULTS {
                let view = store.snapshot();
                let applied = view.applied(A).unwrap().unwrap_or(0);
                for slot in 0..SLOTS {
                    let value = view
                        .get(A, &row(0, slot))
                        .unwrap()
                        .map(|bytes| u64::from_be_bytes(bytes[..].try_into().unwrap()));
                    assert_eq!(value, expected(applied, slot), "slot {slot} at {applied}");
                }
                assert!(applied >= seen, "a later snapshot never goes back");
                seen = applied;
            }
        });
    }

    /// A flipped bit inside a committed batch is not a torn tail: the store
    /// refuses to open rather than drop or replay it.
    #[test]
    fn a_corrupt_committed_batch_stops_recovery() {
        // Incompressible, so the journal holds it as written.
        let mut seed = 0x2545_f491_4f6c_dd1d_u64;
        let value: Vec<u8> = (0..256)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                seed as u8
            })
            .collect();
        let dir = tempfile::tempdir().unwrap();
        {
            let store = Fjall::open(dir.path()).unwrap();
            let mut batch = store.batch();
            batch.apply(A, 1, &[put(row(0, 1), &value)]);
            batch.commit(Durability::Synced).unwrap();
        }
        let mut pending = vec![dir.path().to_path_buf()];
        let mut flipped = false;
        while let Some(path) = pending.pop() {
            for entry in std::fs::read_dir(&path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    pending.push(path);
                    continue;
                }
                if path.extension().is_none_or(|extension| extension != "jnl") {
                    continue;
                }
                let mut bytes = std::fs::read(&path).unwrap();
                if let Some(at) = bytes
                    .windows(value.len())
                    .position(|window| window == value)
                {
                    bytes[at + 100] ^= 0x01;
                    std::fs::write(&path, bytes).unwrap();
                    flipped = true;
                }
            }
        }
        assert!(flipped, "the value is in a journal");
        match Fjall::open(dir.path()) {
            Err(Error::JournalRecovery(fjall::JournalRecoveryError::ChecksumMismatch)) => {}
            Err(other) => panic!("unexpected error: {other:?}"),
            Ok(_) => panic!("opened a store with a corrupt committed batch"),
        }
    }

    fn entry(term: u64, body: &[u8]) -> LogEntry {
        LogEntry::result(term, body.to_vec())
    }

    fn indices(store: &Fjall, agent: AgentId) -> Vec<(u64, u64)> {
        store
            .log_range(agent, 0, u64::MAX, usize::MAX)
            .unwrap()
            .into_iter()
            .map(|(index, entry)| (index, entry.term))
            .collect()
    }

    #[test]
    fn raft_rows_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path()).unwrap();
        assert_eq!(store.raft(A).unwrap(), RaftRows::default());
        let hard = HardState {
            term: 7,
            vote: Some(2),
            commit: 4,
        };
        let membership = Membership {
            index: Some(3),
            members: vec![1, 2, 4],
            joint_old: Some(vec![1, 2, 3]),
        };
        let mut batch = store.batch();
        for index in 1..=5 {
            batch.append(A, index, &entry(index / 2 + 1, &[index as u8]));
        }
        batch.hard_state(A, &hard);
        batch.membership(A, &membership);
        batch.apply(A, 3, &[]);
        batch.commit(Durability::Synced).unwrap();
        let at_start = Membership {
            index: Some(1),
            members: vec![1, 2, 3],
            joint_old: None,
        };
        let mut batch = store.batch();
        batch.compact(A, 2, 2, Some(&at_start));
        batch.commit(Durability::Buffered).unwrap();
        drop(store);

        let store = Fjall::open(dir.path()).unwrap();
        let rows = store.raft(A).unwrap();
        assert_eq!(rows.hard, hard);
        assert_eq!(rows.membership, Some(membership));
        assert_eq!(rows.applied, 3);
        assert_eq!(rows.log_start, (2, 2));
        assert_eq!(rows.log_start_membership, Some(at_start));
        assert_eq!(
            rows.log.iter().map(|(index, _)| *index).collect::<Vec<_>>(),
            vec![3, 4, 5]
        );
        assert_eq!(
            store.raft(B).unwrap(),
            RaftRows::default(),
            "another agent's rows"
        );
    }

    #[test]
    fn truncation_removes_stored_and_batched_entries() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path()).unwrap();
        let mut batch = store.batch();
        for index in 1..=5 {
            batch.append(A, index, &entry(1, b"old"));
        }
        batch.append(B, 9, &entry(1, b"other agent"));
        batch.commit(Durability::Synced).unwrap();
        // One batch appends 6 and 7, then a new leader's write truncates
        // after 4 and appends its own 5.
        let mut batch = store.batch();
        batch.append(A, 6, &entry(1, b"old"));
        batch.append(A, 7, &entry(1, b"old"));
        batch.truncate(A, 4);
        batch.append(A, 5, &entry(2, b"new"));
        batch.commit(Durability::Synced).unwrap();
        assert_eq!(
            indices(&store, A),
            vec![(1, 1), (2, 1), (3, 1), (4, 1), (5, 2)]
        );
        assert_eq!(indices(&store, B), vec![(9, 1)]);
    }

    #[test]
    fn a_log_range_stops_at_its_bytes_but_returns_one_entry() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path()).unwrap();
        let mut batch = store.batch();
        for index in 1..=4 {
            batch.append(A, index, &entry(1, &[0; 100]));
        }
        batch.commit(Durability::Synced).unwrap();
        let range = |max_bytes| {
            store
                .log_range(A, 2, 4, max_bytes)
                .unwrap()
                .into_iter()
                .map(|(index, _)| index)
                .collect::<Vec<_>>()
        };
        assert_eq!(range(1), vec![2]);
        assert_eq!(range(250), vec![2, 3]);
        assert_eq!(range(usize::MAX), vec![2, 3, 4]);
        assert!(store.log_range(A, 5, 9, usize::MAX).unwrap().is_empty());
    }

    #[test]
    fn logs_and_programs_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path()).unwrap();
        let entry = LogEntry::result(3, b"result".to_vec());
        let hash = ProgramHash([5; 32]);
        let mut batch = store.batch();
        batch.append(A, 7, &entry);
        batch.program(&hash, b"blob");
        batch.commit(Durability::Synced).unwrap();
        assert_eq!(store.log_entry(A, 7).unwrap(), Some(entry));
        assert_eq!(store.log_entry(A, 8).unwrap(), None);
        assert_eq!(store.log_entry(B, 7).unwrap(), None);
        assert_eq!(store.program(&hash).unwrap().as_deref(), Some(&b"blob"[..]));
        drop(store);

        let reopened = Fjall::open(dir.path()).unwrap();
        assert_eq!(reopened.log_entry(A, 7).unwrap().unwrap().term, 3);
        assert!(reopened.program(&hash).unwrap().is_some());
    }
}
