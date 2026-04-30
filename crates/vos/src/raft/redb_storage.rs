//! `vos_raft::Storage` adapter backed by redb.
//!
//! Wraps the existing [`super::log::RaftLog`] / [`super::log::RaftMeta`]
//! tables behind the generic [`vos_raft::Storage`] trait. The adapter is
//! the bridge that lets the transport-and-storage-agnostic Raft core in
//! `vos-raft` drive vos's per-replica redb file without the core having
//! to know anything about redb.
//!
//! ## Why an adapter and not "just use redb in vos-raft"
//!
//! `vos-raft` compiles `no_std + alloc` and ships zero non-stdlib deps;
//! redb is std-only and pulls a tree of crates that don't fit on a
//! microcontroller. Keeping the redb integration here preserves that
//! property and lets future hosts (an Embassy-only firmware, an in-RAM
//! simulator) wire their own [`Storage`] without touching this file.
//!
//! ## Atomicity contract
//!
//! [`Storage::commit_batch`] composes every populated field of a
//! [`WriteBatch<u16>`] into a *single* `redb::WriteTransaction`. A crash
//! mid-batch leaves either the pre-batch or the post-batch state on
//! disk — the `truncate → compact → appends → state → meta` ordering
//! that the worker relies on is enforced inside the txn before commit.

use alloc::sync::Arc;
use alloc::vec::Vec;

use redb::Database;
use vos_raft::{LogEntry, Meta, Storage, WriteBatch};

use crate::commit::{CommitError, STATE_KEY, STATE_TABLE};

use super::log::{RaftLog, RaftMeta};

/// `vos_raft::Storage<u16>` impl on top of a shared
/// `Arc<redb::Database>`. Owns its in-memory cache of the log
/// tail + snap pointer + meta scalars + materialized state row;
/// `commit_batch` refreshes them after the txn commits so the
/// cheap reads stay correct.
pub struct RedbStorage {
    db: Arc<Database>,
    log: RaftLog,
    meta: RaftMeta,
    /// Cached actor state row. Mirrors the row written under
    /// [`STATE_TABLE`] / [`STATE_KEY`]. Empty `Vec` = no state
    /// row materialized yet.
    state_cache: Vec<u8>,
}

impl RedbStorage {
    /// Open a `RedbStorage` on `db`, recovering the log tail +
    /// snap pointer + meta scalars + state row from disk. Empty
    /// log / no state row → all zeros / empty `Vec`.
    pub fn open(db: Arc<Database>) -> Result<Self, CommitError> {
        let log = RaftLog::open(db.clone())?;
        let meta = RaftMeta::load(&db)?;
        let state_cache = read_state_bytes(&db)?;
        Ok(Self {
            db,
            log,
            meta,
            state_cache,
        })
    }

    /// Borrow the underlying database. Used by the worker's
    /// snapshot-install path (which reads the state row through
    /// the storage handle rather than caching it).
    pub fn db(&self) -> &Database {
        &self.db
    }
}

impl Storage<u16> for RedbStorage {
    type Error = CommitError;

    fn last_index(&self) -> u64 {
        self.log.last_index()
    }

    fn last_term(&self) -> u64 {
        self.log.last_term()
    }

    fn snap_last_index(&self) -> u64 {
        self.log.snap_last_index()
    }

    fn snap_last_term(&self) -> u64 {
        self.log.snap_last_term()
    }

    async fn term_at(&self, index: u64) -> Result<Option<u64>, Self::Error> {
        self.log.term_at(index)
    }

    async fn entries(&self, start: u64, end: u64) -> Result<Vec<LogEntry>, Self::Error> {
        let raw = self.log.entries(start, end)?;
        Ok(raw
            .into_iter()
            .map(|e| LogEntry {
                index: e.index,
                term: e.term,
                payload: e.payload,
            })
            .collect())
    }

    async fn read_state(&self) -> Result<Vec<u8>, Self::Error> {
        Ok(self.state_cache.clone())
    }

    async fn load_meta(&self) -> Result<Meta<u16>, Self::Error> {
        Ok(meta_from_raft(&self.meta))
    }

    async fn commit_batch(&mut self, batch: WriteBatch<u16>) -> Result<(), Self::Error> {
        // Empty batch: nothing to do. Avoids opening a write txn
        // for a no-op call.
        let touches_log = batch.truncate_after.is_some()
            || batch.compact_to.is_some()
            || !batch.appends.is_empty();
        let touches_state = batch.state.is_some();
        let touches_meta = batch.meta.is_some();
        if !(touches_log || touches_state || touches_meta) {
            return Ok(());
        }

        let txn = self.db.begin_write()?;

        // Order matches the WriteBatch contract:
        //   1) truncate the divergent tail
        //   2) compact below the new snap pointer
        //   3) append the leader's authoritative tail
        //   4) replace state row (snapshot install, or
        //      single-node apply)
        //   5) replace meta scalars
        if let Some(after) = batch.truncate_after {
            self.log.truncate_after_in_txn(&txn, after)?;
        }
        if let Some((idx, term)) = batch.compact_to {
            self.log.compact_to_in_txn(&txn, idx, term)?;
        }
        for entry in &batch.appends {
            // RaftLog::append_in_txn assigns the index from its
            // cached tail rather than honoring `entry.index`. The
            // worker only ever asks us to append at the next slot,
            // so the indices match — but assert to catch a future
            // caller passing something inconsistent.
            let assigned =
                self.log
                    .append_in_txn(&txn, entry.term, &entry.payload)?;
            debug_assert_eq!(
                assigned, entry.index,
                "RedbStorage: append index drift (entry={}, assigned={})",
                entry.index, assigned,
            );
        }
        let new_state = batch.state.as_deref();
        if let Some(state_bytes) = new_state {
            let mut state_table = txn.open_table(STATE_TABLE)?;
            state_table.insert(STATE_KEY, state_bytes)?;
        }
        let new_meta = batch.meta.as_ref().cloned();
        if let Some(m) = &new_meta {
            let raft_meta = raft_from_meta(m);
            raft_meta.write_in_txn(&txn)?;
        }

        txn.commit()?;

        // Refresh in-memory caches now that disk is durable.
        // RaftLog's own caches were updated in-place by
        // {truncate,compact,append}_in_txn, so all that's left is
        // the meta + state row.
        if let Some(m) = new_meta {
            self.meta = raft_from_meta(&m);
        }
        if let Some(state_bytes) = batch.state {
            self.state_cache = state_bytes;
        }
        Ok(())
    }
}

/// Read the post-apply actor state row as raw bytes. Empty `Vec`
/// when no state row has been materialized yet.
fn read_state_bytes(db: &Database) -> Result<Vec<u8>, CommitError> {
    let txn = db.begin_read()?;
    let table = match txn.open_table(STATE_TABLE) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    Ok(table
        .get(STATE_KEY)?
        .map(|v| v.value().to_vec())
        .unwrap_or_default())
}

/// Convert `vos::raft::log::RaftMeta` (vos's own shape) → the
/// generic `vos_raft::Meta<u16>` the trait operates on.
fn meta_from_raft(m: &RaftMeta) -> Meta<u16> {
    Meta {
        current_term: m.current_term,
        voted_for: m.voted_for,
        commit_index: m.commit_index,
        last_applied: m.last_applied,
        snap_last_index: m.snap_last_index,
        snap_last_term: m.snap_last_term,
    }
}

/// Convert `vos_raft::Meta<u16>` → `vos::raft::log::RaftMeta`.
fn raft_from_meta(m: &Meta<u16>) -> RaftMeta {
    RaftMeta {
        current_term: m.current_term,
        voted_for: m.voted_for,
        commit_index: m.commit_index,
        last_applied: m.last_applied,
        snap_last_index: m.snap_last_index,
        snap_last_term: m.snap_last_term,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> (Arc<Database>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(alloc::format!(
            "vos_redb_storage_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.redb");
        let db = Arc::new(Database::create(&path).unwrap());
        (db, dir)
    }

    fn entry(idx: u64, term: u64, p: &[u8]) -> LogEntry {
        LogEntry {
            index: idx,
            term,
            payload: p.to_vec(),
        }
    }

    fn block_on<F: core::future::Future>(f: F) -> F::Output {
        futures_executor::block_on(f)
    }

    #[test]
    fn fresh_storage_reports_empty_state() {
        let (db, dir) = temp_db();
        let s = RedbStorage::open(db).unwrap();
        assert_eq!(s.last_index(), 0);
        assert_eq!(s.last_term(), 0);
        assert_eq!(s.snap_last_index(), 0);
        assert_eq!(s.snap_last_term(), 0);
        assert_eq!(block_on(s.read_state()).unwrap(), Vec::<u8>::new());
        let m = block_on(s.load_meta()).unwrap();
        assert_eq!(m, Meta::<u16>::default());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn append_then_read_roundtrips_through_disk() {
        let (db, dir) = temp_db();
        let mut s = RedbStorage::open(db.clone()).unwrap();
        block_on(s.commit_batch(WriteBatch {
            appends: alloc::vec![
                entry(1, 1, b"a"),
                entry(2, 1, b"b"),
                entry(3, 2, b"c"),
            ],
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(s.last_index(), 3);
        assert_eq!(s.last_term(), 2);
        let raw = block_on(s.entries(1, 3)).unwrap();
        assert_eq!(raw.len(), 3);
        assert_eq!(raw[0].payload, b"a".to_vec());
        drop(s);
        let s2 = RedbStorage::open(db).unwrap();
        assert_eq!(s2.last_index(), 3);
        assert_eq!(s2.last_term(), 2);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn write_batch_atomicity_state_and_meta_advance_together() {
        let (db, dir) = temp_db();
        let mut s = RedbStorage::open(db.clone()).unwrap();
        let m = Meta::<u16> {
            current_term: 4,
            voted_for: Some(7),
            commit_index: 1,
            last_applied: 1,
            snap_last_index: 0,
            snap_last_term: 0,
        };
        block_on(s.commit_batch(WriteBatch {
            appends: alloc::vec![entry(1, 4, b"first")],
            state: Some(b"snapshot-after-first".to_vec()),
            meta: Some(m.clone()),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(block_on(s.read_state()).unwrap(), b"snapshot-after-first".to_vec());
        assert_eq!(block_on(s.load_meta()).unwrap(), m);
        let s2 = RedbStorage::open(db).unwrap();
        assert_eq!(block_on(s2.read_state()).unwrap(), b"snapshot-after-first".to_vec());
        assert_eq!(block_on(s2.load_meta()).unwrap(), m);
        assert_eq!(s2.last_index(), 1);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn truncate_then_append_grafts_new_tail() {
        let (db, dir) = temp_db();
        let mut s = RedbStorage::open(db).unwrap();
        block_on(s.commit_batch(WriteBatch {
            appends: alloc::vec![entry(1, 1, b"a"), entry(2, 1, b"b"), entry(3, 1, b"c")],
            ..Default::default()
        }))
        .unwrap();
        block_on(s.commit_batch(WriteBatch {
            truncate_after: Some(1),
            appends: alloc::vec![entry(2, 2, b"B"), entry(3, 2, b"C")],
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(s.last_index(), 3);
        assert_eq!(s.last_term(), 2);
        assert_eq!(block_on(s.term_at(2)).unwrap(), Some(2));
        assert_eq!(block_on(s.term_at(3)).unwrap(), Some(2));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn compact_drops_head_and_anchors_term() {
        let (db, dir) = temp_db();
        let mut s = RedbStorage::open(db).unwrap();
        block_on(s.commit_batch(WriteBatch {
            appends: alloc::vec![entry(1, 1, b"a"), entry(2, 1, b"b"), entry(3, 2, b"c")],
            ..Default::default()
        }))
        .unwrap();
        block_on(s.commit_batch(WriteBatch {
            compact_to: Some((2, 1)),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(s.snap_last_index(), 2);
        assert_eq!(s.snap_last_term(), 1);
        assert_eq!(block_on(s.term_at(2)).unwrap(), Some(1));
        assert_eq!(block_on(s.term_at(3)).unwrap(), Some(2));
        assert_eq!(block_on(s.term_at(1)).unwrap(), None);
        let _ = std::fs::remove_dir_all(dir);
    }
}
