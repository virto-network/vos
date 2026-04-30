//! One Raft log entry. The payload is opaque to the consensus
//! layer — the state machine that applies committed entries
//! decides how to interpret the bytes.
//!
//! Today this is a fixed `Vec<u8>` payload; a future iteration
//! may parameterize over a `Payload: AsRef<[u8]>` so no-alloc
//! targets can use `heapless::Vec<u8, N>`.

use alloc::vec::Vec;

/// One log entry. `index` is 1-based and contiguous within a
/// group; entries with `index <= snap_last_index` are eligible
/// for compaction once the leader observes a quorum has
/// replicated them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub index: u64,
    pub term: u64,
    /// Application-defined payload. For the VOS integration this
    /// is `EffectLog::to_bytes()`; an embedded user might
    /// serialize a small operation struct.
    pub payload: Vec<u8>,
}
