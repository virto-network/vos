//! Per-replica durable scalars.
//!
//! Plain data — no I/O. The [`crate::storage::Storage`] trait is
//! responsible for getting these to and from disk; this struct is
//! the in-memory shape both sides agree on.

use crate::config::NodeId;

/// Persistent Raft meta state. The set of fields here is the
/// minimum the protocol requires for crash safety; an
/// implementation may store additional bookkeeping (e.g. a
/// `state_persisted_index` follow-up to bound replay) by
/// extending its own per-row format.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta<N: NodeId> {
    /// Latest term the replica has observed. Monotonic.
    pub current_term: u64,
    /// Vote granted in `current_term`. `None` means we haven't
    /// voted yet this term, or we've moved to a new term.
    pub voted_for: Option<N>,
    /// Highest log index known to be replicated to a majority.
    /// Always ≤ `last_log_index`.
    pub commit_index: u64,
    /// Highest log index applied to the state machine. Always
    /// ≤ `commit_index`.
    pub last_applied: u64,
    /// Highest log index that has been compacted out of the
    /// live log. The state at this index lives in the snapshot
    /// row. Always ≤ `last_applied`.
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
            last_applied: 0,
            snap_last_index: 0,
            snap_last_term: 0,
        }
    }
}
