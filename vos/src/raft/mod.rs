//! Raft consensus storage and strategy for VOS actors.
//!
//! The durable layer lives in [`log::RaftLog`] / [`log::RaftMeta`] on redb.
//! [`v2::RaftAccumulateLogV2`] orders canonical JAM service requests and leaves
//! their application to the guest Accumulate entry. The legacy agent runtime
//! still uses the [`CommitStrategy`] implementation in [`strategy::RaftCommit`]
//! until the production-node cutover is complete.

#[cfg(feature = "storage")]
pub mod log;
#[cfg(feature = "storage")]
pub mod redb_storage;
#[cfg(feature = "storage")]
pub mod strategy;
#[cfg(feature = "storage")]
pub mod v2;
#[cfg(all(feature = "storage", feature = "network"))]
pub mod vos_transport;
#[cfg(all(feature = "storage", feature = "network"))]
pub mod worker;

#[cfg(feature = "storage")]
pub use log::{LogEntry, RAFT_LOG, RAFT_META, RaftLog, RaftMeta};
#[cfg(feature = "storage")]
pub use redb_storage::RedbStorage;
#[cfg(feature = "storage")]
pub use strategy::{RaftCommit, RaftConfig};
#[cfg(feature = "storage")]
pub use v2::RaftAccumulateLogV2;
#[cfg(all(feature = "storage", feature = "network"))]
pub use vos_transport::{VosTransport, VosTransportError};
#[cfg(all(feature = "storage", feature = "network"))]
pub use worker::{ChangeMembershipError, RaftWorker, Role, WorkerConfig, WorkerHandle};

/// Read the member set a replica's on-disk Raft db is anchored
/// to, without spawning a worker. `Ok(None)` when the file
/// doesn't exist or no configuration has been persisted — the
/// latter distinguishes a db that actually participated in a
/// group from a husk created by a spawn whose join was rolled
/// back, so a daemon can decide between "respawn with the
/// recorded config" and "redo the join handshake".
///
/// Must only be called while the agent is NOT running — redb
/// holds an exclusive file lock.
#[cfg(feature = "storage")]
pub fn persisted_membership(
    db_path: &std::path::Path,
) -> Result<Option<alloc::vec::Vec<u16>>, crate::commit::CommitError> {
    if !db_path.exists() {
        return Ok(None);
    }
    let db = redb::Database::create(db_path)
        .map_err(|e| crate::commit::CommitError::Config(alloc::format!("open raft db: {e}")))?;
    Ok(log::load_active_config(&db)?.map(|(current, _joint)| current))
}

/// Anchor a brand-new group's configuration before its first
/// spawn. Writes `members` as the persisted active configuration
/// iff none exists; returns whether the row was written. A solo
/// bootstrap that skips this seed has no `ConfigChange` entry and
/// no persisted row, so a later restart would re-derive its
/// member set from spawner-provided state that may have grown in
/// the meantime — leaving the group unable to elect until every
/// listed voter joins.
///
/// Must only be called while the agent is NOT running — redb
/// holds an exclusive file lock.
#[cfg(feature = "storage")]
pub fn seed_initial_config(
    db_path: &std::path::Path,
    members: &[u16],
) -> Result<bool, crate::commit::CommitError> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| crate::commit::CommitError::Config(alloc::format!("create dir: {e}")))?;
    }
    let db = redb::Database::create(db_path)
        .map_err(|e| crate::commit::CommitError::Config(alloc::format!("open raft db: {e}")))?;
    log::seed_active_config(&db, members)
}
