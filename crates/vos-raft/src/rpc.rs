//! Raft RPC request / response types.
//!
//! These are the *content* of a Raft message — pure structs with
//! no wire encoding. The transport layer is responsible for
//! getting bytes from one node to another; this crate just defines
//! what the bytes mean. The `vos` integration packs these into
//! its existing libp2p `Frame` enum; an embedded consumer might
//! serialize them with `serde` over a UART link.

use alloc::vec::Vec;

use crate::log_entry::LogEntry;

/// Raft `AppendEntries` from leader → follower. Empty `entries`
/// is a heartbeat; a non-empty batch is replication. The
/// `prev_log_*` pair anchors the consistency check: the follower
/// must have an entry at `prev_log_index` whose term equals
/// `prev_log_term`, otherwise the request is refused and the
/// leader retries with a smaller `prev_log_index`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppendEntriesReq<N> {
    pub leader: N,
    pub term: u64,
    pub prev_log_index: u64,
    pub prev_log_term: u64,
    pub leader_commit: u64,
    pub entries: Vec<LogEntry>,
}

/// Reply to [`AppendEntriesReq`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AppendEntriesResp {
    pub term: u64,
    pub success: bool,
    /// Highest log index the follower has replicated when
    /// `success` is true. Ignored on `success = false`.
    pub match_index: u64,
}

/// Raft `RequestVote` from candidate → other replicas.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestVoteReq<N> {
    pub candidate: N,
    pub term: u64,
    pub last_log_index: u64,
    pub last_log_term: u64,
}

/// Reply to [`RequestVoteReq`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequestVoteResp {
    pub term: u64,
    pub vote_granted: bool,
}

/// Raft `InstallSnapshot` from leader → follower. Sent when the
/// leader has compacted past the follower's `match_index` and
/// can no longer serve the consistency check from log entries.
/// The follower replaces its state machine with the snapshot
/// bytes, advances meta to `last_included_*`, and drops any log
/// entries the snapshot supersedes.
///
/// Single-shot today (snapshot in one RPC); a future revision
/// will add chunked variants for ultra-constrained or very large
/// snapshot payloads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallSnapshotReq<N> {
    pub leader: N,
    pub term: u64,
    pub last_included_index: u64,
    pub last_included_term: u64,
    /// Opaque snapshot bytes — the application's serialized
    /// state at `last_included_index`.
    pub snapshot: Vec<u8>,
}

/// Reply to [`InstallSnapshotReq`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallSnapshotResp {
    pub term: u64,
}
