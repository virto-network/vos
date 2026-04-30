//! Raft consensus strategy for VOS actors.
//!
//! Phase 1 (this commit): persistent log + meta scalars on top of
//! redb. The agent thread uses the same `CommitStrategy` boundary
//! it already does for `LocalCommit` / `CrdtCommit`; the Raft side
//! lives entirely under [`log::RaftLog`] / [`log::RaftMeta`] until
//! later phases bolt on RPCs, election, and replication.
//!
//! ## Phase roadmap
//!
//! 1. **This commit** — `RaftLog`, `RaftMeta`, redb tables. No
//!    `CommitStrategy` impl yet, no peers, no leader election. Just
//!    the durable storage layer the rest of Raft hangs on top of.
//! 2. `RaftCommit` — single-node `CommitStrategy` (every commit is
//!    self-quorumed; appends + applies + persists state in one
//!    redb txn).
//! 3. Wire frames + RPC plumbing through libp2p `request_response`.
//! 4. Election (`RequestVote`, randomized timeouts).
//! 5. Replication (`AppendEntries`, `matchIndex`).
//! 6. Quorum-aware `commit_with_log` (followers forward to leader,
//!    block until applied).
//! 7. Snapshots + log compaction.
//!
//! Each phase is its own commit and keeps the storage shape from
//! phase 1 stable.

#[cfg(feature = "storage")]
pub mod log;
#[cfg(feature = "storage")]
pub mod strategy;
#[cfg(all(feature = "storage", feature = "network"))]
pub mod worker;

#[cfg(feature = "storage")]
pub use log::{LogEntry, RaftLog, RaftMeta, RAFT_LOG, RAFT_META};
#[cfg(feature = "storage")]
pub use strategy::{RaftCommit, RaftConfig};
#[cfg(all(feature = "storage", feature = "network"))]
pub use worker::{RaftWorker, Role, WorkerConfig, WorkerHandle};
