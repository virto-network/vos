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
    /// Highest log index that has been compacted out of the
    /// live log. The state at this index lives in the snapshot
    /// row. Always ≤ `commit_index`.
    ///
    /// `vos-raft` is a consensus core, not a replicated state
    /// machine — there's no `last_applied` field here because
    /// the worker has no state machine to apply to. The host
    /// (e.g., `vos::raft::RaftCommit`) tracks its own apply
    /// progress in its own meta row and updates it atomically
    /// with the materialized-state write. The worker only
    /// promises that `commit_index` advances are notified to
    /// the [`ApplySink`](crate::ApplySink); it doesn't observe
    /// or persist the apply itself.
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
