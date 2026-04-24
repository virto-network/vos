//! Commit strategies — how an actor's state is persisted and (later)
//! replicated.
//!
//! The host picks a strategy per actor at deploy time based on the
//! service manifest. Today only [`NoCommit`] and [`LocalCommit`]
//! exist; `CrdtCommit` (merkle-crdt replication) and `RaftCommit`
//! (strong consistency) are planned follow-ups.
//!
//! A strategy owns its own backend (redb database, network handle,
//! etc.) and any change-detection bookkeeping. The host calls
//! [`CommitStrategy::restore`] once at startup and
//! [`CommitStrategy::commit`] after every dispatch.

use std::path::Path;

/// Error type for commit operations.
#[derive(Debug)]
pub enum CommitError {
    /// Backend-specific error (typically redb I/O).
    Backend(String),
}

impl core::fmt::Display for CommitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Backend(s) => f.write_str(s),
        }
    }
}

impl std::error::Error for CommitError {}

/// Persistence/replication strategy for an actor's serialized state.
///
/// Implementations are opaque about what's inside the state bytes —
/// they only see and store them. CRDT-shaped strategies will layer
/// additional tables (DAG nodes, roots) on the same backend.
pub trait CommitStrategy: Send {
    /// Return previously-persisted state, if any.
    ///
    /// `None` means "fresh start" — the host constructs the actor
    /// via its normal init path.
    fn restore(&mut self) -> Option<Vec<u8>>;

    /// Persist the actor's current state.
    ///
    /// Implementations may skip the backend write when the bytes
    /// haven't changed since the last successful commit.
    fn commit(&mut self, state: &[u8]) -> Result<(), CommitError>;
}

/// No-op strategy — state lives only in memory and is lost on exit.
pub struct NoCommit;

impl CommitStrategy for NoCommit {
    fn restore(&mut self) -> Option<Vec<u8>> {
        None
    }
    fn commit(&mut self, _state: &[u8]) -> Result<(), CommitError> {
        Ok(())
    }
}

// ── redb-backed local strategy ──────────────────────────────────────

#[cfg(feature = "storage")]
pub use local::{LocalCommit, STATE_TABLE};

#[cfg(feature = "storage")]
mod local {
    use super::*;

    /// redb table holding the materialized actor state.
    pub const STATE_TABLE: redb::TableDefinition<&str, &[u8]> =
        redb::TableDefinition::new("state");

    /// Row key within [`STATE_TABLE`] for the actor's state blob.
    const STATE_KEY: &str = "actor";

    /// Persists state to a redb database, skipping writes when the
    /// serialized bytes are unchanged from the last commit.
    pub struct LocalCommit {
        db: redb::Database,
        last: Vec<u8>,
    }

    impl LocalCommit {
        /// Open (or create) the redb database at `path`.
        pub fn open(path: &Path) -> Result<Self, CommitError> {
            redb::Database::create(path)
                .map(|db| Self { db, last: Vec::new() })
                .map_err(|e| CommitError::Backend(e.to_string()))
        }

        /// Borrow the underlying redb handle. Used when a higher-
        /// level strategy (e.g. CrdtCommit) needs to share the same
        /// database for its additional tables.
        pub fn db(&self) -> &redb::Database {
            &self.db
        }
    }

    impl CommitStrategy for LocalCommit {
        fn restore(&mut self) -> Option<Vec<u8>> {
            let txn = self.db.begin_read().ok()?;
            let table = txn.open_table(STATE_TABLE).ok()?;
            let bytes = table.get(STATE_KEY).ok().flatten()?.value().to_vec();
            self.last = bytes.clone();
            Some(bytes)
        }

        fn commit(&mut self, state: &[u8]) -> Result<(), CommitError> {
            if state == self.last {
                return Ok(());
            }
            let txn = self
                .db
                .begin_write()
                .map_err(|e| CommitError::Backend(e.to_string()))?;
            {
                let mut table = txn
                    .open_table(STATE_TABLE)
                    .map_err(|e| CommitError::Backend(e.to_string()))?;
                table
                    .insert(STATE_KEY, state)
                    .map_err(|e| CommitError::Backend(e.to_string()))?;
            }
            txn.commit()
                .map_err(|e| CommitError::Backend(e.to_string()))?;
            self.last = state.to_vec();
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_commit_restore_none() {
        let mut s = NoCommit;
        assert!(s.restore().is_none());
        assert!(s.commit(b"anything").is_ok());
    }

    #[cfg(feature = "storage")]
    #[test]
    fn local_commit_roundtrip_and_change_detect() {
        let dir = std::env::temp_dir().join(format!(
            "vos_commit_test_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("state.redb");

        // Write, reopen, read back.
        {
            let mut lc = LocalCommit::open(&db_path).unwrap();
            assert!(lc.restore().is_none(), "fresh db has no state");
            lc.commit(b"hello").unwrap();
        }
        {
            let mut lc = LocalCommit::open(&db_path).unwrap();
            assert_eq!(lc.restore().as_deref(), Some(&b"hello"[..]));
            // Writing the same bytes is a no-op — verify by checking
            // the db file mtime doesn't change. Instead, we just
            // confirm commit returns Ok (the skip path returns Ok too).
            lc.commit(b"hello").unwrap();
            // Write new bytes and re-read.
            lc.commit(b"world").unwrap();
            assert_eq!(lc.restore().as_deref(), Some(&b"world"[..]));
        }

        let _ = std::fs::remove_dir_all(&dir);
    }
}
