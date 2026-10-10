//! Snapshot transfer between replicas, which the driver streams outside the
//! protocol core: chunks from the leader, and acknowledgements that say how
//! much the receiver holds. Pure structs; the transport encodes them.

use alloc::vec::Vec;

use crate::config::NodeId;

/// A chunk of a snapshot from leader to follower, sent when the leader has
/// compacted past the follower's acknowledged index.
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
///
/// ## Membership
///
/// Snapshots ferry the leader's `effective_cfg` so a follower
/// whose first activity is an InstallSnapshot at a high index
/// can learn the cluster membership at that point — the snapshot
/// bytes are opaque to the consensus layer, so without this the
/// follower would have to fall back to its static `Config::members`
/// (potentially wrong if the cluster has changed shape since
/// boot). The leader copies these from its in-memory active
/// configuration together with the exact log index that established it; the
/// follower writes them via
/// `WriteBatch::active_config` in the same atomic install batch
/// as the snap-pointer advance. Only present on the FINAL chunk
/// (`done = true`) — intermediate chunks leave them empty / None.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallSnapshotReq<N: NodeId> {
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
    /// Cluster membership represented by the snapshot. The leader fills this
    /// from `effective_cfg.current` only when its provenance is at or before
    /// `last_included_index`; otherwise it omits membership rather than
    /// exporting a speculative view. Only meaningful on the final chunk
    /// (`done = true`). An empty Vec means no new membership authority: the
    /// follower retains its effective view but clears any provenance that was
    /// speculative before this install.
    pub members: Vec<N>,
    /// Joint-old set belonging to the supplied membership, otherwise `None`.
    /// Mirrors `EntryKind::ConfigChange::joint_old`.
    pub joint_old: Option<Vec<N>>,
    /// Log/snapshot index that established `members`/`joint_old`. This is
    /// present exactly when membership is supplied and must not exceed
    /// `last_included_index`. The follower preserves this exact provenance;
    /// installing a later snapshot must not make a speculative configuration
    /// appear committed merely by moving `commit_index` forward.
    pub active_config_index: Option<u64>,
}

/// A receiver's acknowledgement of snapshot chunks: how many bytes it holds
/// of the snapshot it names.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InstallSnapshotResp {
    pub term: u64,
    pub last_included_index: u64,
    pub last_included_term: u64,
    /// Bytes the receiver has assembled for this snapshot; the sender resumes
    /// from here. `0` after a refusal or a restart.
    pub bytes_received: u64,
}
