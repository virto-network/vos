//! One Raft log entry. The payload is opaque to the consensus
//! layer — the state machine that applies committed entries
//! decides how to interpret the bytes.

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
    /// Cluster-membership transition (Ongaro thesis §4.3) to
    /// `members`, joint with `joint_old` while that is set (see
    /// [`ActiveConfigRecord`](crate::ActiveConfigRecord)). The core
    /// appends these for a membership change and takes its quorum
    /// view from them; an application's apply skips entries whose
    /// `kind` isn't `Data`.
    ConfigChange {
        joint_old: Option<Vec<N>>,
        members: Vec<N>,
    },
}

impl<N: NodeId> LogEntry<N> {
    /// Construct an `EntryKind::Data` entry.
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
}
