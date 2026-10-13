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
    /// Term of the entry at `snap_last_index`. Used by
    /// AppendEntries consistency checks anchored on the snap
    /// boundary post-compaction.
    pub snap_last_term: u64,
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
