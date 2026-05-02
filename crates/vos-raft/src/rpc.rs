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

/// Raft `PreVote` from a would-be candidate → other replicas.
///
/// PreVote (Ongaro thesis §9.6) prevents term inflation from a
/// flapping partition. A node that suspects a leader failure
/// first asks "would you vote for me at `next_term`?" *without*
/// bumping its own `current_term` or persisting `voted_for`.
/// Only if a quorum of replies say yes does it transition to
/// Candidate, bump term, and send real `RequestVote`s.
///
/// Without PreVote: a partitioned follower whose link flaps will
/// time out, become Candidate at term+1, get isolated again,
/// time out at term+2, etc. — and when it rejoins, its inflated
/// term forces the working leader to step down. With PreVote,
/// the would-be candidate's preliminary check returns "no, I
/// have a healthy leader" and the term stays put.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreVoteReq<N> {
    pub candidate: N,
    /// The term the candidate WOULD bump to if granted. The
    /// receiver does NOT adopt this term — it just answers the
    /// hypothetical.
    pub next_term: u64,
    pub last_log_index: u64,
    pub last_log_term: u64,
}

/// Reply to [`PreVoteReq`]. Replicas grant a pre-vote when the
/// requester's log is at least as up-to-date as theirs AND they
/// haven't heard from a leader recently (their election timer
/// hasn't been reset). If the candidate is in fact stale, the
/// replier's `term` lets it learn the current term and skip the
/// pointless real election.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PreVoteResp {
    /// The replier's `current_term`. Used by the candidate to
    /// learn it's stale and skip starting a real election.
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
/// **Chunked**. A snapshot that exceeds the transport's frame
/// budget is split across multiple `InstallSnapshotReq`s with
/// the same `(last_included_index, last_included_term)` identity.
/// Each chunk carries its byte `offset` into the assembled
/// snapshot; the final chunk sets `done = true`. The follower
/// buffers chunks under that identity, then atomically commits
/// the assembled snapshot when `done` arrives.
///
/// Re-sent chunks (same offset) are idempotent. A new identity
/// from the same leader supersedes the in-flight buffer; a stale
/// identity (`last_included_index <= snap_last_index`) is a
/// no-op.
///
/// Receivers MAY refuse out-of-order chunks (offset != current
/// buffer length) by returning `bytes_received = current
/// buffer.len()`; the leader resumes from there. The default
/// in-crate impl assumes strict in-order delivery and resets if
/// the offset doesn't match.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallSnapshotReq<N> {
    pub leader: N,
    pub term: u64,
    pub last_included_index: u64,
    pub last_included_term: u64,
    /// Byte offset of this chunk into the assembled snapshot.
    /// `0` for the first chunk; subsequent chunks set this to
    /// the offset returned by the previous response.
    pub offset: u64,
    /// `true` for the final chunk. The follower commits the
    /// assembled snapshot only when it sees `done = true` AND
    /// the cumulative offset+len matches the leader's intent.
    pub done: bool,
    /// Bytes for *this chunk only* (not the whole snapshot).
    pub data: Vec<u8>,
}

/// Reply to [`InstallSnapshotReq`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallSnapshotResp {
    pub term: u64,
    /// How many bytes the follower has accumulated for the
    /// current `(last_included_index, last_included_term)`
    /// identity. The leader uses this to set the next chunk's
    /// `offset` (resuming after a dropped chunk, or skipping
    /// past chunks the follower already has).
    ///
    /// `0` if the follower rejected the request (stale term,
    /// identity changed, or chunk arrived out of order).
    pub bytes_received: u64,
}
