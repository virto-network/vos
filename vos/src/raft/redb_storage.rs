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
//! disk — the `truncate → compact → appends → state → meta → config`
//! ordering that the worker relies on is enforced inside the txn
//! before commit.

use alloc::sync::Arc;
use alloc::vec::Vec;

use redb::Database;
use vos_raft::{EntryKind, LogEntry, Meta, Storage, WriteBatch};

use crate::commit::{CommitError, STATE_KEY, STATE_TABLE};

use super::log::{RaftLog, RaftMeta};

/// On-disk discriminant for the kind of payload a `raft_log` row
/// carries. Stored as the first byte of the row's value (after
/// the `[term: u64 LE]` prefix `RaftLog::append_in_txn` adds).
/// Mirrors the wire-side `RAFT_ENTRY_KIND_*` constants in
/// `crate::network::wire`. Cleanly separates application data
/// from membership transitions so the apply path can skip the
/// latter without parsing them as `EffectLog` blobs.
pub(crate) const ENTRY_KIND_DATA: u8 = 0;
pub(crate) const ENTRY_KIND_CONFIG_CHANGE: u8 = 1;

/// Encode a `vos_raft::EntryKind<u16>` to its on-disk byte
/// sequence. The leading byte is the kind tag; the rest is
/// variant-specific. Mirrors the wire format in
/// `crate::network::wire`.
pub(crate) fn encode_entry_kind(kind: &EntryKind<u16>) -> Vec<u8> {
    match kind {
        EntryKind::Data { payload } => {
            let mut buf = Vec::with_capacity(1 + payload.len());
            buf.push(ENTRY_KIND_DATA);
            buf.extend_from_slice(payload);
            buf
        }
        EntryKind::ConfigChange { joint_old, members } => {
            let cap =
                1 + 1 + joint_old.as_ref().map_or(0, |v| 2 + 2 * v.len()) + 2 + 2 * members.len();
            let mut buf = Vec::with_capacity(cap);
            buf.push(ENTRY_KIND_CONFIG_CHANGE);
            match joint_old {
                Some(prev) => {
                    buf.push(1);
                    buf.extend_from_slice(&(prev.len() as u16).to_le_bytes());
                    for n in prev {
                        buf.extend_from_slice(&n.to_le_bytes());
                    }
                }
                None => buf.push(0),
            }
            buf.extend_from_slice(&(members.len() as u16).to_le_bytes());
            for n in members {
                buf.extend_from_slice(&n.to_le_bytes());
            }
            buf
        }
        // Future variants land here as the consensus core grows.
        // Mark the byte sequence empty + a `Data { payload: [] }`
        // shape so older replicas reading the row don't choke;
        // the worker will reject the unknown kind tag if/when it
        // matters.
        _ => alloc::vec![ENTRY_KIND_DATA],
    }
}

/// Decode a `vos_raft::EntryKind<u16>` from its on-disk byte
/// sequence. Returns `Err` if the tag is unknown or the body
/// is malformed — the caller treats those as storage corruption.
pub(crate) fn decode_entry_kind(bytes: &[u8]) -> Result<EntryKind<u16>, CommitError> {
    let (tag, rest) = bytes.split_first().ok_or_else(|| {
        CommitError::Config("raft_log entry: empty payload (missing kind tag)".into())
    })?;
    match *tag {
        ENTRY_KIND_DATA => Ok(EntryKind::Data {
            payload: rest.to_vec(),
        }),
        ENTRY_KIND_CONFIG_CHANGE => {
            let mut pos = 0;
            let joint_old_present = *rest.get(pos).ok_or_else(|| {
                CommitError::Config("raft_log ConfigChange: missing joint_old flag".into())
            })?;
            pos += 1;
            let joint_old = match joint_old_present {
                0 => None,
                1 => {
                    let len_bytes = rest.get(pos..pos + 2).ok_or_else(|| {
                        CommitError::Config("raft_log ConfigChange: truncated joint_old len".into())
                    })?;
                    pos += 2;
                    let len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
                    let mut v = Vec::with_capacity(len);
                    for _ in 0..len {
                        let b = rest.get(pos..pos + 2).ok_or_else(|| {
                            CommitError::Config(
                                "raft_log ConfigChange: truncated joint_old prefix".into(),
                            )
                        })?;
                        pos += 2;
                        v.push(u16::from_le_bytes([b[0], b[1]]));
                    }
                    Some(v)
                }
                other => {
                    return Err(CommitError::Config(alloc::format!(
                        "raft_log ConfigChange: invalid joint_old flag {other}",
                    )));
                }
            };
            let len_bytes = rest.get(pos..pos + 2).ok_or_else(|| {
                CommitError::Config("raft_log ConfigChange: truncated members len".into())
            })?;
            pos += 2;
            let len = u16::from_le_bytes([len_bytes[0], len_bytes[1]]) as usize;
            let mut members = Vec::with_capacity(len);
            for _ in 0..len {
                let b = rest.get(pos..pos + 2).ok_or_else(|| {
                    CommitError::Config("raft_log ConfigChange: truncated members prefix".into())
                })?;
                pos += 2;
                members.push(u16::from_le_bytes([b[0], b[1]]));
            }
            if pos != rest.len() {
                return Err(CommitError::Config(alloc::format!(
                    "raft_log ConfigChange: {} trailing bytes",
                    rest.len() - pos,
                )));
            }
            Ok(EntryKind::ConfigChange { joint_old, members })
        }
        other => Err(CommitError::Config(alloc::format!(
            "raft_log entry: unknown kind tag {other}",
        ))),
    }
}

/// `vos_raft::Storage<u16>` impl on top of a shared
/// `Arc<redb::Database>`. Caches the log tail + snap pointer + meta
/// scalars (these are fast-path reads the worker hits every loop
/// iteration). The materialized state row is *not* cached and is
/// re-read from disk on every `read_state` call.
///
/// ## Why state isn't cached
///
/// vos has two writers for the state row sharing the same `db`
/// handle:
///
/// 1. The worker, via `commit_batch.state` (snapshot install).
/// 2. `RaftCommit::commit_with_log`, which writes the state row in
///    its own txn after the leader's quorum-commit unblocks.
///
/// If the worker cached `state_cache` at open time and only refreshed
/// it on its own writes, an outbound `InstallSnapshot` would ship
/// stale bytes — the leader's `read_state` would return the cache
/// from the moment the worker spawned, not the post-`commit_with_log`
/// row that's actually on disk. Re-reading on every `read_state`
/// keeps the leader's snapshot bytes consistent with the materialized
/// state, at the cost of one extra read txn per snapshot send (rare).
pub struct RedbStorage {
    db: Arc<Database>,
    log: RaftLog,
    meta: RaftMeta,
}

impl RedbStorage {
    /// Open a `RedbStorage` on `db`, recovering the log tail +
    /// snap pointer + meta scalars from disk. Empty log → all
    /// zeros.
    pub fn open(db: Arc<Database>) -> Result<Self, CommitError> {
        let log = RaftLog::open(db.clone())?;
        let meta = RaftMeta::load(&db)?;
        Ok(Self { db, log, meta })
    }

    /// Borrow the underlying database. Used by the worker's
    /// snapshot-install path and by tests that introspect the
    /// raw redb tables.
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

    async fn entries(&self, start: u64, end: u64) -> Result<Vec<LogEntry<u16>>, Self::Error> {
        let raw = self.log.entries(start, end)?;
        let mut out = Vec::with_capacity(raw.len());
        for e in raw {
            let kind = decode_entry_kind(&e.payload)?;
            out.push(LogEntry {
                index: e.index,
                term: e.term,
                kind,
            });
        }
        Ok(out)
    }

    async fn read_state(&self) -> Result<Vec<u8>, Self::Error> {
        // Re-read every time. Vos's `RaftCommit::commit_with_log`
        // writes the state row in its own txn, out-of-band of the
        // worker's `commit_batch`, so a cached copy here would go
        // stale and the leader would ship the pre-`commit_with_log`
        // bytes to a fresh follower over `InstallSnapshot`. One
        // read txn per snapshot send is cheap; snapshot sends are
        // rare.
        read_state_bytes(&self.db)
    }

    async fn load_meta(&self) -> Result<Meta<u16>, Self::Error> {
        Ok(meta_from_raft(&self.meta))
    }

    async fn active_config(&self) -> Result<Option<(Vec<u16>, Option<Vec<u16>>)>, Self::Error> {
        super::log::load_active_config(&self.db)
    }

    async fn commit_batch(&mut self, batch: WriteBatch<u16>) -> Result<(), Self::Error> {
        // Empty batch: nothing to do. Avoids opening a write txn
        // for a no-op call.
        let touches_log = batch.truncate_after.is_some()
            || batch.compact_to.is_some()
            || !batch.appends.is_empty();
        let touches_state = batch.state.is_some();
        let touches_meta = batch.meta.is_some();
        let touches_config = batch.active_config.is_some();
        if !(touches_log || touches_state || touches_meta || touches_config) {
            return Ok(());
        }

        // Snapshot the RaftLog cache *before* any mutation. The
        // `*_in_txn` helpers update `self.log.{last_index,
        // last_term, snap_last_*}` in place; if the txn commit
        // fails (or any earlier step inside the closure errors),
        // we restore the snapshot so the cache stays consistent
        // with disk.
        let cache_snap = self.log.cache_snapshot();

        let new_meta = batch.meta.as_ref().cloned();
        let new_state = batch.state.clone();
        let new_config = batch.active_config.clone();
        let mut do_txn = || -> Result<(), CommitError> {
            let txn = self.db.begin_write()?;

            // Order matches the WriteBatch contract:
            //   1) truncate the divergent tail
            //   2) compact below the new snap pointer
            //   3) append the leader's authoritative tail
            //   4) replace state row (snapshot install, or
            //      single-node apply)
            //   5) replace meta scalars
            //   6) persist the adopted active configuration
            if let Some(after) = batch.truncate_after {
                self.log.truncate_after_in_txn(&txn, after)?;
            }
            if let Some((idx, term)) = batch.compact_to {
                self.log.compact_to_in_txn(&txn, idx, term)?;
            }
            for entry in &batch.appends {
                // `RaftLog::append_in_txn` assigns the index from
                // its cached tail rather than honoring
                // `entry.index`. The worker only ever asks us to
                // append at the next slot, so the indices match
                // — but `debug_assert_eq` catches a future caller
                // passing something inconsistent.
                //
                // The on-disk format prefixes a one-byte kind tag
                // (see `encode_entry_kind`) so a follower's apply
                // path can distinguish application data from
                // membership transitions and skip the latter.
                let on_disk = encode_entry_kind(&entry.kind);
                let assigned = self.log.append_in_txn(&txn, entry.term, &on_disk)?;
                debug_assert_eq!(
                    assigned, entry.index,
                    "RedbStorage: append index drift (entry={}, assigned={})",
                    entry.index, assigned,
                );
            }
            if let Some(state_bytes) = new_state.as_deref() {
                let mut state_table = txn.open_table(STATE_TABLE)?;
                state_table.insert(STATE_KEY, state_bytes)?;
            }
            if let Some(m) = &new_meta {
                // Merge the worker-managed fields into the
                // existing on-disk RaftMeta (preserves
                // `last_applied`, which the worker doesn't
                // manage). The actual write skips
                // META_LAST_APPLIED.
                let raft_meta = raft_from_meta(&self.meta, m);
                raft_meta.write_worker_fields_in_txn(&txn)?;
            }
            if let Some((current, joint_old)) = &new_config {
                // Persisting the adopted configuration in the
                // same txn keeps it atomic with the log mutation
                // that produced it, and lets boot recovery survive
                // compaction past the last `ConfigChange` entry.
                super::log::write_active_config_in_txn(&txn, current, joint_old.as_deref())?;
            }

            txn.commit()?;
            Ok(())
        };

        // Closure can't borrow `self` mutably twice, so structure
        // it as a fn-pointer-style call: `do_txn` already captures
        // `&mut self.log` through `self.log.*_in_txn(&txn, …)`.
        // Run, then restore on error.
        if let Err(e) = do_txn() {
            self.log.cache_restore(cache_snap);
            return Err(e);
        }

        // Refresh in-memory caches now that disk is durable.
        // RaftLog's own caches were updated in-place by
        // {truncate,compact,append}_in_txn — kept on success. The
        // state row is intentionally not cached (see `read_state`).
        if let Some(m) = new_meta {
            // Re-merge with the cached `last_applied` so the
            // in-memory cache stays consistent with disk
            // (which we just wrote without touching
            // META_LAST_APPLIED).
            self.meta = raft_from_meta(&self.meta, &m);
        }
        let _ = new_state;
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
/// generic `vos_raft::Meta<u16>` the trait operates on. Drops
/// `last_applied` — the worker doesn't track it; vos's
/// `RaftCommit` reads/writes it on its own.
fn meta_from_raft(m: &RaftMeta) -> Meta<u16> {
    Meta {
        current_term: m.current_term,
        voted_for: m.voted_for,
        commit_index: m.commit_index,
        snap_last_index: m.snap_last_index,
        snap_last_term: m.snap_last_term,
    }
}

/// Convert `vos_raft::Meta<u16>` → `vos::raft::log::RaftMeta`,
/// preserving the existing `last_applied` from `prev` (the
/// worker doesn't manage it). Used internally to keep the
/// in-memory cache consistent; the on-disk write path uses
/// [`RaftMeta::write_worker_fields_in_txn`] which simply
/// doesn't touch `META_LAST_APPLIED`.
fn raft_from_meta(prev: &RaftMeta, m: &Meta<u16>) -> RaftMeta {
    RaftMeta {
        current_term: m.current_term,
        voted_for: m.voted_for,
        commit_index: m.commit_index,
        last_applied: prev.last_applied,
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

    fn entry(idx: u64, term: u64, p: &[u8]) -> LogEntry<u16> {
        LogEntry::data(idx, term, p.to_vec())
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
            appends: alloc::vec![entry(1, 1, b"a"), entry(2, 1, b"b"), entry(3, 2, b"c"),],
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(s.last_index(), 3);
        assert_eq!(s.last_term(), 2);
        let raw = block_on(s.entries(1, 3)).unwrap();
        assert_eq!(raw.len(), 3);
        assert_eq!(raw[0].payload(), Some(b"a".as_ref()));
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
        assert_eq!(
            block_on(s.read_state()).unwrap(),
            b"snapshot-after-first".to_vec()
        );
        assert_eq!(block_on(s.load_meta()).unwrap(), m);
        let s2 = RedbStorage::open(db).unwrap();
        assert_eq!(
            block_on(s2.read_state()).unwrap(),
            b"snapshot-after-first".to_vec()
        );
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
    fn read_state_picks_up_out_of_band_writes() {
        // Vos's `RaftCommit::commit_with_log` writes the state row
        // in its own txn, separately from the worker's
        // `commit_batch`. RedbStorage must re-read on every
        // `read_state` so the leader's outbound `InstallSnapshot`
        // ships current bytes, not whatever was on disk when the
        // worker last touched the row.
        let (db, dir) = temp_db();
        let mut s = RedbStorage::open(db.clone()).unwrap();

        // Worker writes v1 through commit_batch.
        block_on(s.commit_batch(WriteBatch {
            state: Some(b"worker-v1".to_vec()),
            ..Default::default()
        }))
        .unwrap();
        assert_eq!(block_on(s.read_state()).unwrap(), b"worker-v1".to_vec());

        // Out-of-band writer (mimicking `RaftCommit::commit_with_log`)
        // overwrites the state row WITHOUT going through the
        // RedbStorage instance.
        {
            let txn = db.begin_write().unwrap();
            {
                let mut t = txn.open_table(STATE_TABLE).unwrap();
                t.insert(STATE_KEY, b"out-of-band-v2".as_slice()).unwrap();
            }
            txn.commit().unwrap();
        }

        // Without the cache, `read_state` reflects the new on-disk
        // value immediately. (Pre-fix this returned the stale
        // `b"worker-v1"`.)
        assert_eq!(
            block_on(s.read_state()).unwrap(),
            b"out-of-band-v2".to_vec()
        );

        let _ = std::fs::remove_dir_all(dir);
    }

    // ── Sprint 5 — crash-recovery tests ──────────────────────
    //
    // The existing tests above drop the `RedbStorage` and re-open
    // a new one from the *same* `Arc<Database>` handle. That misses
    // the real production restart path: the redb file is closed,
    // every handle is gone, and a fresh `Database::create` reopens
    // it from disk. Tests below exercise that path and the
    // failed-commit cache-restore branch (`do_txn().is_err()`
    // around line 335).

    /// Open a redb database at `path`, returning the Arc handle.
    /// Distinct from `temp_db()` (which generates a fresh dir);
    /// this one reopens the same physical file across calls.
    fn open_at(path: &std::path::Path) -> Arc<Database> {
        Arc::new(Database::create(path).unwrap())
    }

    /// Allocate a fresh temp dir + path WITHOUT opening the
    /// database yet. Callers open + close handles inside their
    /// own scopes so the OS-level file release is deterministic.
    fn temp_db_path() -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(alloc::format!(
            "vos_redb_restart_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.redb");
        (path, dir)
    }

    #[test]
    fn durability_across_full_process_restart() {
        // Write log + state + meta, drop *every* handle so the
        // redb file is fully closed, then re-open from path and
        // assert all three categories survived. This is the real
        // "daemon restart" durability contract; if a regression
        // batched a write into RAM-only and only flushed on Drop,
        // this test would catch it.
        let (path, dir) = temp_db_path();
        let m = Meta::<u16> {
            current_term: 7,
            voted_for: Some(11),
            commit_index: 2,
            snap_last_index: 0,
            snap_last_term: 0,
        };

        {
            let db = open_at(&path);
            let mut s = RedbStorage::open(db).unwrap();
            block_on(s.commit_batch(WriteBatch {
                appends: alloc::vec![
                    entry(1, 7, b"alpha"),
                    entry(2, 7, b"beta"),
                    entry(3, 7, b"gamma"),
                ],
                state: Some(b"state-after-3".to_vec()),
                meta: Some(m.clone()),
                ..Default::default()
            }))
            .unwrap();
            // `s` and `db` go out of scope here — Drop closes redb.
        }

        {
            let db = open_at(&path);
            let s = RedbStorage::open(db).unwrap();
            assert_eq!(s.last_index(), 3, "log tail must survive restart");
            assert_eq!(s.last_term(), 7);
            assert_eq!(
                block_on(s.read_state()).unwrap(),
                b"state-after-3".to_vec(),
                "state row must survive restart",
            );
            assert_eq!(
                block_on(s.load_meta()).unwrap(),
                m,
                "meta scalars must survive restart",
            );
            let raw = block_on(s.entries(1, 3)).unwrap();
            assert_eq!(raw.len(), 3);
            assert_eq!(raw[2].payload(), Some(b"gamma".as_ref()));
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn failed_commit_reverts_in_memory_cache_and_disk_unchanged() {
        // Induce a commit failure mid-batch (truncate below the
        // snap pointer is a hard error per `truncate_after_in_txn`)
        // and verify:
        //   1. `commit_batch` returns Err.
        //   2. The in-memory cache (`last_index`, `snap_last_*`)
        //      is restored to its pre-batch state.
        //   3. On a full restart from disk, the storage shows the
        //      same pre-batch state — i.e. the failed batch's
        //      partial work didn't leak through.
        // A regression that lost the `cache_restore(cache_snap)`
        // call would fail (2); a regression that committed the
        // txn before the validation would fail (3).
        let (path, dir) = temp_db_path();
        {
            let db = open_at(&path);
            let mut s = RedbStorage::open(db).unwrap();
            // First, set up a snap pointer at index 5. Compact
            // runs BEFORE append within a single batch (per the
            // WriteBatch contract), and `compact_to` bumps the
            // cached last_index — so the appends + compact must
            // be split into two batches.
            block_on(s.commit_batch(WriteBatch {
                appends: alloc::vec![
                    entry(1, 1, b"a"),
                    entry(2, 1, b"b"),
                    entry(3, 1, b"c"),
                    entry(4, 1, b"d"),
                    entry(5, 1, b"e"),
                ],
                ..Default::default()
            }))
            .unwrap();
            block_on(s.commit_batch(WriteBatch {
                compact_to: Some((5, 1)),
                ..Default::default()
            }))
            .unwrap();
            // Sanity: state matches expectation.
            assert_eq!(s.last_index(), 5);
            assert_eq!(s.snap_last_index(), 5);
            assert_eq!(s.snap_last_term(), 1);

            // Now attempt a batch that MUST fail: truncate_after(2)
            // is below the snap pointer at 5.
            let err = block_on(s.commit_batch(WriteBatch {
                truncate_after: Some(2),
                appends: alloc::vec![entry(6, 2, b"f")],
                ..Default::default()
            }));
            assert!(err.is_err(), "truncate below snap_last_index must fail",);

            // Cache must be restored to pre-batch state.
            assert_eq!(
                s.last_index(),
                5,
                "failed batch must not advance last_index"
            );
            assert_eq!(s.last_term(), 1);
            assert_eq!(s.snap_last_index(), 5);
        }

        // Restart from disk — the failed batch's partial work
        // (truncate, append, whatever) must not be visible.
        {
            let db = open_at(&path);
            let s = RedbStorage::open(db).unwrap();
            assert_eq!(
                s.last_index(),
                5,
                "post-restart last_index must match pre-failure",
            );
            assert_eq!(s.snap_last_index(), 5);
            // Index 6 must not be on disk.
            let entries_above = block_on(s.entries(6, 6)).unwrap();
            assert!(
                entries_above.is_empty(),
                "failed batch's append must not be persisted; got {entries_above:?}",
            );
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn compact_then_restart_then_append_continues_log_correctly() {
        // The compact-then-restart path is the snapshot install
        // recovery flow: leader installs a snapshot at (idx=N,
        // term=T), the follower restarts, and subsequent appends
        // must continue from N+1 with the right term anchor.
        // A regression where snap_last_index doesn't survive
        // restart would cause `term_at(N)` to return `None`
        // after reopen.
        let (path, dir) = temp_db_path();
        {
            let db = open_at(&path);
            let mut s = RedbStorage::open(db).unwrap();
            // Two batches — compact must follow appends in its
            // own batch (in-batch ordering is truncate→compact→
            // append, and compact bumps the cached last_index).
            block_on(s.commit_batch(WriteBatch {
                appends: alloc::vec![entry(1, 1, b"a"), entry(2, 1, b"b"), entry(3, 2, b"c"),],
                ..Default::default()
            }))
            .unwrap();
            block_on(s.commit_batch(WriteBatch {
                compact_to: Some((2, 1)),
                ..Default::default()
            }))
            .unwrap();
            assert_eq!(s.snap_last_index(), 2);
            assert_eq!(s.last_index(), 3);
        }
        // Restart.
        {
            let db = open_at(&path);
            let mut s = RedbStorage::open(db).unwrap();
            assert_eq!(
                s.snap_last_index(),
                2,
                "snap_last_index must survive restart",
            );
            assert_eq!(s.snap_last_term(), 1);
            assert_eq!(s.last_index(), 3);
            // term_at(2) must come from the snap pointer (the
            // entry itself was compacted away).
            assert_eq!(block_on(s.term_at(2)).unwrap(), Some(1));
            assert_eq!(block_on(s.term_at(3)).unwrap(), Some(2));

            // Continue appending past the restart.
            block_on(s.commit_batch(WriteBatch {
                appends: alloc::vec![entry(4, 2, b"d"), entry(5, 3, b"e"),],
                ..Default::default()
            }))
            .unwrap();
            assert_eq!(s.last_index(), 5);
            assert_eq!(s.last_term(), 3);
        }
        // Restart again — full history (snap + post-restart
        // appends) must all be visible.
        {
            let db = open_at(&path);
            let s = RedbStorage::open(db).unwrap();
            assert_eq!(s.last_index(), 5);
            assert_eq!(s.last_term(), 3);
            assert_eq!(s.snap_last_index(), 2);
            let raw = block_on(s.entries(3, 5)).unwrap();
            assert_eq!(raw.len(), 3, "got entries: {raw:?}");
            assert_eq!(raw[0].payload(), Some(b"c".as_ref()));
            assert_eq!(raw[2].payload(), Some(b"e".as_ref()));
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn active_config_persists_in_batch_and_survives_restart() {
        // The worker hands the adopted configuration through
        // `WriteBatch::active_config`; the storage must surface it
        // again via `Storage::active_config` after a full reopen —
        // that's what lets boot recovery survive compaction past
        // the last `ConfigChange` entry.
        let (path, dir) = temp_db_path();
        {
            let db = open_at(&path);
            let mut s = RedbStorage::open(db).unwrap();
            assert_eq!(block_on(s.active_config()).unwrap(), None);
            block_on(s.commit_batch(WriteBatch {
                appends: alloc::vec![LogEntry::config_change(
                    1,
                    1,
                    Some(alloc::vec![0xAAAA]),
                    alloc::vec![0xAAAA, 0xBBBB],
                )],
                active_config: Some((alloc::vec![0xAAAA, 0xBBBB], Some(alloc::vec![0xAAAA]))),
                ..Default::default()
            }))
            .unwrap();
            assert_eq!(
                block_on(s.active_config()).unwrap(),
                Some((alloc::vec![0xAAAA, 0xBBBB], Some(alloc::vec![0xAAAA]))),
            );
        }
        {
            let db = open_at(&path);
            let s = RedbStorage::open(db).unwrap();
            assert_eq!(
                block_on(s.active_config()).unwrap(),
                Some((alloc::vec![0xAAAA, 0xBBBB], Some(alloc::vec![0xAAAA]))),
                "active config must survive restart",
            );
        }
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
