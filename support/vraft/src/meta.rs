//! Per-replica durable scalars.
//!
//! Plain data, no I/O: the host stores these fields and gives them
//! back at recovery.

use crate::config::NodeId;

/// Persistent Raft meta state: the minimum the protocol requires
/// for crash safety.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta<N: NodeId> {
    /// Latest term the replica has observed. Monotonic.
    pub current_term: u64,
    /// Vote granted in `current_term`. `None` means we haven't
    /// voted yet this term, or we've moved to a new term.
    pub voted_for: Option<N>,
    /// Highest log index known to be replicated to a majority. The
    /// stored value may pass the log's end after the host cut it at
    /// open; the core clamps it.
    pub commit_index: u64,
    /// Highest log index compacted out of the log. Always ≤ `commit_index`.
    pub snap_last_index: u64,
    /// Term of the entry at `snap_last_index`: an append's previous entry
    /// at the log's start matches against it.
    pub snap_last_term: u64,
}

/// What one of the core's writes records of the meta state: the term, the
/// vote and the commit index. The snapshot pointer is the host's alone,
/// moved only by a compaction and a snapshot switch, so a write never
/// carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HardState<N: NodeId> {
    pub current_term: u64,
    pub voted_for: Option<N>,
    pub commit_index: u64,
}

impl<N: NodeId> Default for Meta<N> {
    fn default() -> Self {
        Self {
            current_term: 0,
            voted_for: None,
            commit_index: 0,
            snap_last_index: 0,
            snap_last_term: 0,
        }
    }
}
