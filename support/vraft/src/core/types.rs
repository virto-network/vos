//! What a host exchanges with the core: the actions it carries out, the
//! answers to its requests, what it recovers, and a replica's status.

use alloc::vec::Vec;

use super::ActiveConfigRecord;
use crate::config::NodeId;
use crate::log_entry::LogEntry;
use crate::message::Message;
use crate::meta::{HardState, Meta};
use crate::role::Role;

/// Why a proposal was not appended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProposeError {
    /// This replica is not the leader, or is handing leadership over.
    NotLeader,
    /// The replica's host stopped it (its store failed, or it shut down).
    /// The core never returns it.
    Stopped,
}

/// Why a read index was not granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReadIndexError {
    NotLeader,
    /// The leader stepped down before a quorum confirmed it.
    LeaderStepped,
    /// Too many reads are queued.
    Backpressure,
    /// The read's deadline passed first.
    TimedOut,
    /// The replica's host stopped it. The core never returns it.
    Stopped,
}

/// Why a membership change was not started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChangeMembershipError {
    NotLeader,
    /// Another change is still in progress.
    InProgress,
    EmptyConfig,
    /// A member is named twice: each counts once toward a quorum.
    DuplicateMember,
    /// The replica's host stopped it. The core never returns it.
    Stopped,
}

/// One ordered write. A host applies it atomically: truncate, then append,
/// then the meta and configuration rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Write<N: NodeId> {
    pub seq: u64,
    pub truncate_after: Option<u64>,
    pub entries: Vec<LogEntry<N>>,
    /// The term, vote and commit index; the snapshot pointer is the
    /// host's, which only a compaction and a snapshot switch move.
    pub meta: Option<HardState<N>>,
    pub active_config: Option<ActiveConfigRecord<N>>,
    /// Whether the write must be synced before it counts: entries, terms and
    /// votes are; a commit-index move alone is not.
    pub sync: bool,
}

/// A request for log entries the core's cache no longer holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Load {
    pub from: u64,
    pub to: u64,
    /// The term the request was made in; older results are dropped.
    pub term: u64,
    /// The host may return a shorter prefix within this many bytes, but at
    /// least one entry.
    pub max_bytes: usize,
}

/// The answer to a request the host made with a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Propose {
        token: u64,
        result: Result<u64, ProposeError>,
    },
    ReadIndex {
        token: u64,
        result: Result<u64, ReadIndexError>,
    },
    ChangeMembership {
        token: u64,
        result: Result<u64, ChangeMembershipError>,
    },
}

/// What the host must do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action<N: NodeId> {
    Write(Write<N>),
    Send {
        to: N,
        message: Message<N>,
    },
    LoadEntries(Load),
    /// Entries through `index` may be applied.
    Committed {
        index: u64,
    },
    /// Stream this replica's state, as of the snapshot through `index`, to
    /// `to`, with the configuration it holds.
    SendSnapshot {
        to: N,
        index: u64,
        term: u64,
        configuration: Option<ActiveConfigRecord<N>>,
    },
    /// The log may be compacted through `through`. `configuration` is the
    /// one in effect there, when known, which the host keeps with the log's
    /// start: a later truncation that removes every configuration entry
    /// above it falls back to it.
    CompactBound {
        through: u64,
        configuration: Option<ActiveConfigRecord<N>>,
    },
    Answer(Answer),
    Changed {
        term: u64,
        role: Role,
        leader: Option<N>,
    },
}

/// The rows a host's snapshot switch writes in the same atomic batch as
/// the state: drop the log after `truncate_after` (when the log disagrees
/// at the snapshot's index), then the meta and the membership record.
/// Only [`Core::snapshot_switch`](super::Core::snapshot_switch) makes one,
/// and [`Core::snapshot_installed`](super::Core::snapshot_installed) takes
/// it back once it is durable.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotSwitch<N: NodeId> {
    pub truncate_after: Option<u64>,
    /// With the snapshot's last index and its term.
    pub meta: Meta<N>,
    pub active_config: ActiveConfigRecord<N>,
    /// The configuration in effect at the snapshot's index, when known,
    /// kept with the log's start.
    pub log_start_config: Option<ActiveConfigRecord<N>>,
    /// Whether `active_config` is the one the snapshot carried.
    pub(super) carried: bool,
}

/// What a replica recovers from its store.
#[derive(Debug, Clone)]
pub struct Recovered<N: NodeId> {
    pub meta: Meta<N>,
    /// The live log, from the snapshot boundary on.
    pub entries: Vec<LogEntry<N>>,
    pub active_config: Option<ActiveConfigRecord<N>>,
    /// The configuration in effect at the log's start, if the host kept it.
    pub log_start_config: Option<ActiveConfigRecord<N>>,
    /// The highest applied index recovered.
    pub applied: u64,
    /// The last log position (index, term) a replica held before its host
    /// wiped its log and state, keeping its term and vote: it votes only
    /// for candidates whose log reaches it, and campaigns only once its
    /// own log does, as if it still held that log. A host that wipes a
    /// replica a change removed keeps it, so the replica, added again
    /// empty, never votes for a removed one that never learned of its
    /// removal, nor leads by a configuration older than one it held.
    pub vote_floor: Option<(u64, u64)>,
}

impl<N: NodeId> Default for Recovered<N> {
    fn default() -> Self {
        Self {
            meta: Meta::default(),
            entries: Vec::new(),
            active_config: None,
            log_start_config: None,
            applied: 0,
            vote_floor: None,
        }
    }
}

/// A diagnostic view of a replica.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Status<N: NodeId> {
    pub role: Role,
    pub current_term: u64,
    pub voted_for: Option<N>,
    pub last_log_index: u64,
    pub commit_index: u64,
    pub snap_last_index: u64,
    pub durable_index: u64,
    pub members: Vec<N>,
    pub joint_old: Option<Vec<N>>,
    pub active_config_index: Option<u64>,
    pub leader_hint: Option<N>,
    /// Messages dropped since the replica started: what no correct peer
    /// sends, and what it does not take from outside its configuration
    /// (answers, and vote requests while it hears a leader).
    pub refused: u64,
}
