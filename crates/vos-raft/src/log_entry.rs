//! One Raft log entry. The payload is opaque to the consensus
//! layer — the state machine that applies committed entries
//! decides how to interpret the bytes.
//!
//! Parameterized over `N: NodeId` so config-change entries can
//! carry typed member sets alongside the regular data payload.
//! Pure-data callers don't see the parameter — they just produce
//! `LogEntry::data(...)`.

use alloc::vec::Vec;

use crate::config::NodeId;

/// One log entry. `index` is 1-based and contiguous within a
/// group; entries with `index <= snap_last_index` are eligible
/// for compaction once the leader observes a quorum has
/// replicated them.
///
/// Most entries are `EntryKind::Data` carrying an application
/// payload; future versions will add `EntryKind::ConfigChange`
/// entries produced by membership-change APIs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry<N: NodeId> {
    pub index: u64,
    pub term: u64,
    pub kind: EntryKind<N>,
}

/// What kind of entry sits in the log at this index.
///
/// Storage layers serialize this as a one-byte tag prefixed to
/// the body. Tag values reserved by this crate:
/// - `0` = `Data`
/// - `1` = `ConfigChange` (reserved for the upcoming
///   joint-consensus implementation; not yet emitted by the
///   worker)
///
/// `#[non_exhaustive]` because future Raft features may add
/// more kinds.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EntryKind<N: NodeId> {
    /// Application data — the consensus layer doesn't interpret
    /// the payload bytes.
    Data { payload: Vec<u8> },
    /// Cluster-membership transition (Ongaro thesis §4.3).
    /// `members` is the configuration the cluster transitions
    /// *to*. If `joint_old` is `Some`, the cluster is in a
    /// joint-consensus state — quorum decisions require
    /// agreement from both `joint_old` AND `members` until a
    /// follow-up `ConfigChange { joint_old: None, .. }` retires
    /// the joint phase.
    ///
    /// Reserved variant: emitted by a forthcoming
    /// `WorkerHandle::change_membership(...)` API and consumed
    /// by the worker itself to update its quorum view.
    /// Application apply-sinks should ignore entries whose
    /// `kind` isn't `Data`.
    ConfigChange {
        joint_old: Option<Vec<N>>,
        members: Vec<N>,
    },
}

impl<N: NodeId> LogEntry<N> {
    /// Construct an `EntryKind::Data` entry. The most common
    /// constructor — every application-payload entry uses it.
    pub fn data(index: u64, term: u64, payload: Vec<u8>) -> Self {
        Self {
            index,
            term,
            kind: EntryKind::Data { payload },
        }
    }

    /// Borrow the entry's data payload, if it's a `Data` entry.
    /// Returns `None` for `ConfigChange` entries — apply sinks
    /// can use this to skip non-data entries cleanly.
    pub fn payload(&self) -> Option<&[u8]> {
        match &self.kind {
            EntryKind::Data { payload } => Some(payload),
            _ => None,
        }
    }
}
