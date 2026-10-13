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
/// group; each replica compacts on its own through the lower of
/// its commit and what it has applied durably.
///
/// Most entries are `EntryKind::Data` carrying an application
/// payload; a membership change adds `EntryKind::ConfigChange`
/// entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry<N: NodeId> {
    pub index: u64,
    pub term: u64,
    pub kind: EntryKind<N>,
}

/// What an entry holds: application data, or a membership change.
#[derive(Debug, Clone, PartialEq, Eq)]
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
    /// The core appends these for a membership change and takes
    /// its quorum view from them; an application's apply skips
    /// entries whose `kind` isn't `Data`.
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

    /// Construct an `EntryKind::ConfigChange` entry. `joint_old`
    /// = `Some(...)` produces the joint-phase entry; `None`
    /// produces the final non-joint entry that retires a joint
    /// phase.
    pub fn config_change(
        index: u64,
        term: u64,
        joint_old: Option<Vec<N>>,
        members: Vec<N>,
    ) -> Self {
        Self {
            index,
            term,
            kind: EntryKind::ConfigChange { joint_old, members },
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
