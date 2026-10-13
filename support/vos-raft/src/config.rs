//! Per-replica configuration for one Raft group.

use alloc::vec::Vec;
use core::fmt::Debug;
use core::hash::Hash;

/// A member's identity: cheap to copy, compare and hash, as a primitive
/// integer is.
pub trait NodeId: Copy + Eq + Ord + Hash + Debug + Send + Sync + 'static {}
impl<T> NodeId for T where T: Copy + Eq + Ord + Hash + Debug + Send + Sync + 'static {}

/// Per-replica configuration, built by [`Config::new`] with its defaults.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config<N: NodeId> {
    /// This replica's identity, one of `members`.
    pub me: N,
    /// The group's members while neither its log nor its snapshot names a
    /// configuration: the same set at every replica. A group of one elects
    /// itself at once.
    pub members: Vec<N>,
    /// The election timeout's range in milliseconds. Default: 150 to 300.
    pub election_timeout_ms: (u64, u64),
    /// A leader's heartbeat interval in milliseconds. Default: 50.
    pub heartbeat_interval_ms: u64,
    /// Entries through the compaction bound, the lower of the commit and
    /// what the host applied durably, past the log's start that make a
    /// compaction due. Default: 16.
    pub compact_hysteresis: u64,
    /// Bytes of those entries, as the cache counts them, that make a
    /// compaction due. A host that compacts short of the bound keeps well under this,
    /// or every commit makes one due. Default: 64 MiB.
    pub compact_bytes: u64,
    /// Ask for pre-votes before an election, so a flapping partition does
    /// not inflate terms. Default: `true`.
    pub pre_vote: bool,
    /// The most reads a leader holds; more are refused with
    /// [`ReadIndexError::Backpressure`](crate::core::ReadIndexError::Backpressure).
    /// Default: 1024.
    pub max_pending_reads: usize,
    /// Pre-vote rounds that may time out before a pre-candidate reverts to
    /// follower; `0` never reverts. Default: 3.
    pub pre_candidate_misses_before_revert: u32,
    /// The most inline entry bytes one append carries; an append always
    /// carries at least one entry. Default: 1 MiB.
    pub max_append_bytes: usize,
    /// How long a leader waits for an append's acknowledgement before it
    /// sends again. Default: 1 s.
    pub resend_timeout_ms: u64,
    /// How long a leader waits for a peer to acknowledge a snapshot before
    /// it starts over. Default: 60 s.
    pub snapshot_timeout_ms: u64,
    /// Bytes of recent entries the core keeps in memory; older ones are
    /// loaded from the host's store when a lagging peer needs them.
    /// Default: 16 MiB.
    pub cache_bytes: usize,
    /// A leader that has not heard from a quorum within an election timeout
    /// steps down. Default: `true`.
    pub check_quorum: bool,
    /// A leader sends heartbeats to every follower each interval. When
    /// off, it skips a follower that holds every entry and the commit
    /// while no read waits, and arms no heartbeat deadline once it skips
    /// them all: the host vouches for the leader instead
    /// ([`crate::core::Core::vouch`]). Default: `true`.
    pub idle_heartbeats: bool,
}

impl<N: NodeId> Config<N> {
    /// A configuration with every default.
    pub fn new(me: N, members: Vec<N>) -> Self {
        Self {
            me,
            members,
            election_timeout_ms: (150, 300),
            heartbeat_interval_ms: 50,
            compact_hysteresis: 16,
            compact_bytes: 64 << 20,
            pre_vote: true,
            max_pending_reads: 1024,
            pre_candidate_misses_before_revert: 3,
            max_append_bytes: 1 << 20,
            resend_timeout_ms: 1_000,
            snapshot_timeout_ms: 60_000,
            cache_bytes: 16 << 20,
            check_quorum: true,
            idle_heartbeats: true,
        }
    }
}
