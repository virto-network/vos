//! Persistent Raft log + meta scalars on top of redb.
//!
//! Phase 1 storage layer: durable log of `EffectLog` payloads keyed
//! by 1-based, contiguous index, plus the four scalars Raft needs to
//! survive a crash (`current_term`, `voted_for`, `commit_index`,
//! `last_applied`). No election, no replication, no snapshots —
//! that machinery layers on top of these tables in later phases.
//!
//! Tables live in the same redb file as `STATE_TABLE` so a single
//! txn can append a log entry, advance `last_applied`, and write
//! the post-apply actor state atomically. A crash between dispatches
//! either rolls all three back together or commits all three.

use alloc::sync::Arc;
use alloc::vec::Vec;
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition};

use crate::commit::CommitError;

/// Per-entry: `[term: u64 LE][payload: EffectLog::to_bytes()]`.
/// Index is the redb key, so range scans get it for free.
pub const RAFT_LOG: TableDefinition<u64, &[u8]> =
    TableDefinition::new("raft_log");

/// Meta scalars table — one row per scalar, key is the scalar name.
///
/// Phase 1 keys: `"current_term"`, `"voted_for"`, `"commit_index"`,
/// `"last_applied"`. Phase 6 adds `"snap_last_index"` /
/// `"snap_last_term"`.
pub const RAFT_META: TableDefinition<&str, &[u8]> =
    TableDefinition::new("raft_meta");

const META_TERM: &str = "current_term";
const META_VOTED_FOR: &str = "voted_for";
const META_COMMIT_INDEX: &str = "commit_index";
const META_LAST_APPLIED: &str = "last_applied";
const META_SNAP_INDEX: &str = "snap_last_index";
const META_SNAP_TERM: &str = "snap_last_term";

/// One Raft log entry. Index is 1-based and contiguous.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEntry {
    pub index: u64,
    pub term: u64,
    /// `EffectLog::to_bytes()` — same wire format the CRDT path
    /// already uses, so the apply loop can hand it to the actor's
    /// dispatch unchanged.
    pub payload: Vec<u8>,
}

impl LogEntry {
    fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(8 + self.payload.len());
        buf.extend_from_slice(&self.term.to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }

    fn decode(index: u64, bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 8 {
            return None;
        }
        let term = u64::from_le_bytes(bytes[..8].try_into().ok()?);
        Some(Self {
            index,
            term,
            payload: bytes[8..].to_vec(),
        })
    }
}

/// Persistent Raft log. Wraps the `RAFT_LOG` redb table and caches
/// the tail (`last_index`, `last_term`) plus the snapshot pointer
/// (`snap_last_index`, `snap_last_term`) to keep append + lookup
/// cheap. The cache is recomputed on `open` from the on-disk table
/// state and from `RaftMeta`.
pub struct RaftLog {
    db: Arc<Database>,
    last_index: u64,
    last_term: u64,
    /// Highest log index that has been compacted away. Entries
    /// with index ≤ snap_last_index are no longer in `RAFT_LOG`;
    /// `term_at(snap_last_index)` returns
    /// [`snap_last_term`](Self::snap_last_term) so consistency
    /// checks can still anchor on the boundary entry.
    snap_last_index: u64,
    snap_last_term: u64,
}

impl RaftLog {
    /// Open the log on the given database, recovering the cached
    /// tail + snapshot pointer from disk. Empty log →
    /// `last_index = 0`, `last_term = 0`, `snap_last_* = 0`.
    pub fn open(db: Arc<Database>) -> Result<Self, CommitError> {
        let txn = db.begin_read()?;
        let (last_index_raw, last_term_raw) = match txn.open_table(RAFT_LOG) {
            Ok(t) => match t.last()? {
                Some((k, v)) => {
                    let entry = LogEntry::decode(k.value(), v.value()).ok_or_else(|| {
                        CommitError::Config(alloc::format!(
                            "raft_log tail row failed to decode (index {})",
                            k.value(),
                        ))
                    })?;
                    (entry.index, entry.term)
                }
                None => (0, 0),
            },
            Err(redb::TableError::TableDoesNotExist(_)) => (0, 0),
            Err(e) => return Err(e.into()),
        };
        // Pull snap pointer from RaftMeta directly so RaftLog +
        // RaftMeta agree on the boundary without requiring callers
        // to thread it through.
        let (snap_last_index, snap_last_term) = match txn.open_table(RAFT_META) {
            Ok(t) => {
                let snap_idx = t.get(META_SNAP_INDEX)?.map(|v| u64_le(v.value())).unwrap_or(0);
                let snap_term = t.get(META_SNAP_TERM)?.map(|v| u64_le(v.value())).unwrap_or(0);
                (snap_idx, snap_term)
            }
            Err(redb::TableError::TableDoesNotExist(_)) => (0, 0),
            Err(e) => return Err(e.into()),
        };
        // After compaction the table is empty for `1..=snap_last_index`,
        // so an empty table doesn't mean "no entries" — it means
        // "everything was compacted into the snapshot". Treat the
        // snap pointer as the effective tail when the table is empty.
        let (last_index, last_term) = if last_index_raw == 0 && snap_last_index > 0 {
            (snap_last_index, snap_last_term)
        } else {
            (last_index_raw, last_term_raw)
        };
        Ok(Self {
            db,
            last_index,
            last_term,
            snap_last_index,
            snap_last_term,
        })
    }

    /// Highest index that's been compacted out of `RAFT_LOG`.
    /// Entries with index > this are still in the table.
    pub fn snap_last_index(&self) -> u64 {
        self.snap_last_index
    }

    /// Term of the entry at `snap_last_index`. Used by AppendEntries
    /// consistency checks that anchor on the snap boundary.
    pub fn snap_last_term(&self) -> u64 {
        self.snap_last_term
    }

    pub fn last_index(&self) -> u64 {
        self.last_index
    }

    pub fn last_term(&self) -> u64 {
        self.last_term
    }

    /// Append one entry inside the caller-supplied write txn. Caller
    /// is responsible for committing the txn — that lets us batch
    /// `append_in_txn` + `RaftMeta::write_in_txn` + state-table write
    /// in a single atomic txn so a crash in the middle leaves the log,
    /// the meta scalars, and the materialized state mutually consistent.
    pub fn append_in_txn(
        &mut self,
        txn: &redb::WriteTransaction,
        term: u64,
        payload: &[u8],
    ) -> Result<u64, CommitError> {
        let index = self.last_index + 1;
        let value = LogEntry {
            index,
            term,
            payload: payload.to_vec(),
        }
        .encode();
        txn.open_table(RAFT_LOG)?
            .insert(index, value.as_slice())?;
        self.last_index = index;
        self.last_term = term;
        Ok(index)
    }

    /// Read entries `[start..=end]` in index order. Indices that
    /// have been compacted away (index ≤ `snap_last_index`) are
    /// silently skipped — callers asking for those should fall
    /// back to a snapshot install (later phase) or accept that
    /// only the post-snapshot tail of the requested range is
    /// returned.
    pub fn entries(&self, start: u64, end: u64) -> Result<Vec<LogEntry>, CommitError> {
        if start > end {
            return Ok(Vec::new());
        }
        let effective_start = start.max(self.snap_last_index + 1);
        if effective_start > end {
            return Ok(Vec::new());
        }
        let txn = self.db.begin_read()?;
        let table = match txn.open_table(RAFT_LOG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::with_capacity((end - effective_start + 1) as usize);
        for kv in table.range(effective_start..=end)? {
            let (k, v) = kv?;
            let entry = LogEntry::decode(k.value(), v.value()).ok_or_else(|| {
                CommitError::Config(alloc::format!(
                    "raft_log entry at index {} failed to decode",
                    k.value(),
                ))
            })?;
            out.push(entry);
        }
        Ok(out)
    }

    /// Compact the log up to and including `up_to_index`. Drops
    /// every row in `RAFT_LOG` with index ≤ `up_to_index`,
    /// records the snap pointer in `RAFT_META` so a follow-on
    /// `term_at(up_to_index)` still returns
    /// `Some(up_to_term)`, and refreshes the cached
    /// `snap_last_*` fields. No-op when `up_to_index` ≤ the
    /// current snap pointer (idempotent retries are safe).
    ///
    /// Caller is responsible for the wisdom of the choice —
    /// compacting past a follower's `match_index` strands that
    /// follower (it'll need a snapshot install to catch up,
    /// which lands in a later phase). The worker computes
    /// `min(match_index across followers, own last_index)`
    /// before calling this.
    pub fn compact_to_in_txn(
        &mut self,
        txn: &redb::WriteTransaction,
        up_to_index: u64,
        up_to_term: u64,
    ) -> Result<(), CommitError> {
        if up_to_index <= self.snap_last_index {
            return Ok(());
        }
        // Compaction past `last_index` is the snapshot-install case
        // — a stale follower receiving the leader's authoritative
        // state covering entries it never had. Drop everything we
        // have (it's all <= up_to_index by definition) and set the
        // pointer; subsequent appends will land at index
        // `up_to_index + 1` because last_index now equals the snap
        // pointer.
        {
            let mut table = txn.open_table(RAFT_LOG)?;
            let drop_to = up_to_index.min(self.last_index);
            for k in (self.snap_last_index + 1)..=drop_to {
                table.remove(k)?;
            }
        }
        {
            let mut meta = txn.open_table(RAFT_META)?;
            meta.insert(META_SNAP_INDEX, &up_to_index.to_le_bytes()[..])?;
            meta.insert(META_SNAP_TERM, &up_to_term.to_le_bytes()[..])?;
        }
        self.snap_last_index = up_to_index;
        self.snap_last_term = up_to_term;
        // After a compact-past-last_index install, `last_index`
        // jumps to the snap pointer — entries 1..=up_to_index are
        // gone *and* there were no entries past them. Without this
        // bump, an immediately-following propose would try to
        // append at `last_index + 1`, which would collide with the
        // snap-covered range instead of going to `up_to_index + 1`.
        if up_to_index > self.last_index {
            self.last_index = up_to_index;
            self.last_term = up_to_term;
        }
        Ok(())
    }

    /// Total entry count, read straight from redb. Used by tests
    /// that assert "exactly N entries on disk after N inc()s".
    pub fn len(&self) -> Result<u64, CommitError> {
        let txn = self.db.begin_read()?;
        match txn.open_table(RAFT_LOG) {
            Ok(t) => Ok(t.len()?),
            Err(redb::TableError::TableDoesNotExist(_)) => Ok(0),
            Err(e) => Err(e.into()),
        }
    }

    /// Term of the entry at `index`, or `None` if the index is
    /// out of range. Index 0 is the implicit pre-log slot — both
    /// sides agree it has term 0, which lets a leader send the
    /// very first entry with `prev_log_index=0`/`prev_log_term=0`.
    /// `index == snap_last_index` returns the snap term so
    /// consistency checks anchored on the boundary still resolve
    /// after a compaction. `index < snap_last_index` returns
    /// `None` — the entry is gone, the leader must send a
    /// snapshot or an entry past the boundary.
    pub fn term_at(&self, index: u64) -> Result<Option<u64>, CommitError> {
        if index == 0 {
            return Ok(Some(0));
        }
        if index < self.snap_last_index {
            return Ok(None);
        }
        if index == self.snap_last_index && self.snap_last_index > 0 {
            return Ok(Some(self.snap_last_term));
        }
        if index > self.last_index {
            return Ok(None);
        }
        let txn = self.db.begin_read()?;
        let table = match txn.open_table(RAFT_LOG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let row = table.get(index)?;
        Ok(row
            .and_then(|v| LogEntry::decode(index, v.value()))
            .map(|e| e.term))
    }

    /// Truncate all entries with `index > from_index` inside the
    /// caller-supplied write txn. Refreshes the cached
    /// `last_index` / `last_term` to reflect the post-truncate
    /// tail. Used by a follower whose leader's `AppendEntries`
    /// claims a different entry at an overlapping index — the
    /// follower drops its stale tail before grafting the leader's
    /// authoritative version.
    pub fn truncate_after_in_txn(
        &mut self,
        txn: &redb::WriteTransaction,
        from_index: u64,
    ) -> Result<(), CommitError> {
        if from_index >= self.last_index {
            return Ok(());
        }
        if from_index < self.snap_last_index {
            return Err(CommitError::Config(alloc::format!(
                "raft_log truncate: refused to drop entries past the snap pointer \
                 (from_index={from_index} < snap_last_index={})",
                self.snap_last_index,
            )));
        }
        let new_last_term = if from_index == 0 {
            0
        } else if from_index == self.snap_last_index {
            self.snap_last_term
        } else {
            let table = txn.open_table(RAFT_LOG)?;
            match table.get(from_index)? {
                Some(row) => LogEntry::decode(from_index, row.value())
                    .ok_or_else(|| {
                        CommitError::Config(alloc::format!(
                            "raft_log truncate: row at index {from_index} \
                             failed to decode",
                        ))
                    })?
                    .term,
                None => {
                    return Err(CommitError::Config(alloc::format!(
                        "raft_log truncate: row at index {from_index} \
                         missing before truncate",
                    )));
                }
            }
        };
        {
            let mut table = txn.open_table(RAFT_LOG)?;
            for k in (from_index + 1)..=self.last_index {
                table.remove(k)?;
            }
        }
        self.last_index = from_index;
        self.last_term = new_last_term;
        Ok(())
    }
}

/// Durable Raft scalars. Loaded once at boot, written under the same
/// txn that appends a log entry so they advance atomically.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RaftMeta {
    pub current_term: u64,
    /// libp2p `node_prefix` of the peer we voted for in `current_term`,
    /// or `None` if no vote cast. Always `None` in phase 1.
    pub voted_for: Option<u16>,
    pub commit_index: u64,
    pub last_applied: u64,
    /// Highest log index that's been compacted out of `RAFT_LOG`.
    /// Mirrors `RaftLog::snap_last_index`. Persisted so a worker
    /// restart can reconstruct the snap pointer without scanning
    /// the table.
    pub snap_last_index: u64,
    /// Term of the entry at `snap_last_index`. Used by
    /// AppendEntries consistency checks anchored on the
    /// snap boundary.
    pub snap_last_term: u64,
}

impl RaftMeta {
    pub fn load(db: &Database) -> Result<Self, CommitError> {
        let txn = db.begin_read()?;
        let mut m = Self::default();
        let table = match txn.open_table(RAFT_META) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(m),
            Err(e) => return Err(e.into()),
        };
        if let Some(v) = table.get(META_TERM)? {
            m.current_term = u64_le(v.value());
        }
        if let Some(v) = table.get(META_VOTED_FOR)? {
            let bytes = v.value();
            if bytes.len() == 2 {
                m.voted_for = Some(u16::from_le_bytes([bytes[0], bytes[1]]));
            }
        }
        if let Some(v) = table.get(META_COMMIT_INDEX)? {
            m.commit_index = u64_le(v.value());
        }
        if let Some(v) = table.get(META_LAST_APPLIED)? {
            m.last_applied = u64_le(v.value());
        }
        if let Some(v) = table.get(META_SNAP_INDEX)? {
            m.snap_last_index = u64_le(v.value());
        }
        if let Some(v) = table.get(META_SNAP_TERM)? {
            m.snap_last_term = u64_le(v.value());
        }
        Ok(m)
    }

    pub fn write_in_txn(&self, txn: &redb::WriteTransaction) -> Result<(), CommitError> {
        let mut t = txn.open_table(RAFT_META)?;
        t.insert(META_TERM, &self.current_term.to_le_bytes()[..])?;
        match self.voted_for {
            Some(p) => {
                t.insert(META_VOTED_FOR, &p.to_le_bytes()[..])?;
            }
            None => {
                t.remove(META_VOTED_FOR)?;
            }
        };
        t.insert(META_COMMIT_INDEX, &self.commit_index.to_le_bytes()[..])?;
        t.insert(META_LAST_APPLIED, &self.last_applied.to_le_bytes()[..])?;
        t.insert(META_SNAP_INDEX, &self.snap_last_index.to_le_bytes()[..])?;
        t.insert(META_SNAP_TERM, &self.snap_last_term.to_le_bytes()[..])?;
        Ok(())
    }
}

fn u64_le(b: &[u8]) -> u64 {
    let mut a = [0u8; 8];
    let n = b.len().min(8);
    a[..n].copy_from_slice(&b[..n]);
    u64::from_le_bytes(a)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_db() -> (Arc<Database>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(alloc::format!(
            "vos_raft_log_{}_{}",
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

    #[test]
    fn empty_log_has_index_zero() {
        let (db, dir) = temp_db();
        let log = RaftLog::open(db).unwrap();
        assert_eq!(log.last_index(), 0);
        assert_eq!(log.last_term(), 0);
        assert_eq!(log.len().unwrap(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn append_and_recover_tail_after_reopen() {
        let (db, dir) = temp_db();
        // Append three entries under term 1.
        {
            let mut log = RaftLog::open(db.clone()).unwrap();
            for i in 1..=3 {
                let txn = db.begin_write().unwrap();
                let payload = alloc::format!("entry-{i}");
                let idx = log
                    .append_in_txn(&txn, 1, payload.as_bytes())
                    .unwrap();
                txn.commit().unwrap();
                assert_eq!(idx, i);
            }
            assert_eq!(log.last_index(), 3);
        }
        // Reopen — cached tail must come back from disk.
        let log = RaftLog::open(db.clone()).unwrap();
        assert_eq!(log.last_index(), 3);
        assert_eq!(log.last_term(), 1);
        let entries = log.entries(1, 3).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].index, 1);
        assert_eq!(entries[0].term, 1);
        assert_eq!(entries[0].payload, b"entry-1");
        assert_eq!(entries[2].payload, b"entry-3");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn entries_range_clamps_to_existing_indices() {
        let (db, dir) = temp_db();
        let mut log = RaftLog::open(db.clone()).unwrap();
        let txn = db.begin_write().unwrap();
        log.append_in_txn(&txn, 1, b"only").unwrap();
        txn.commit().unwrap();
        // Range starting beyond the log returns empty.
        assert!(log.entries(2, 5).unwrap().is_empty());
        // Range collapsed (start > end) also returns empty.
        assert!(log.entries(2, 1).unwrap().is_empty());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn compact_drops_entries_and_preserves_boundary_term() {
        let (db, dir) = temp_db();
        let mut log = RaftLog::open(db.clone()).unwrap();
        // Append 5 entries: terms 1, 1, 2, 2, 3.
        let terms = [1u64, 1, 2, 2, 3];
        for t in terms {
            let txn = db.begin_write().unwrap();
            log.append_in_txn(&txn, t, b"x").unwrap();
            txn.commit().unwrap();
        }
        assert_eq!(log.last_index(), 5);
        assert_eq!(log.snap_last_index(), 0);

        // Compact up to index 3 (term 2).
        let txn = db.begin_write().unwrap();
        log.compact_to_in_txn(&txn, 3, 2).unwrap();
        txn.commit().unwrap();
        assert_eq!(log.snap_last_index(), 3);
        assert_eq!(log.snap_last_term(), 2);

        // term_at on the boundary still returns Some(2); below
        // returns None; above reads the table normally.
        assert_eq!(log.term_at(0).unwrap(), Some(0));
        assert_eq!(log.term_at(2).unwrap(), None,
            "compacted-away entry must report None");
        assert_eq!(log.term_at(3).unwrap(), Some(2),
            "snap boundary returns snap_last_term");
        assert_eq!(log.term_at(4).unwrap(), Some(2));
        assert_eq!(log.term_at(5).unwrap(), Some(3));
        assert_eq!(log.term_at(6).unwrap(), None);

        // Range read silently skips compacted entries.
        let entries = log.entries(1, 5).unwrap();
        assert_eq!(entries.len(), 2,
            "only entries 4 and 5 survive the compaction");
        assert_eq!(entries[0].index, 4);
        assert_eq!(entries[1].index, 5);

        // Reopen — snap pointer comes back from RaftMeta.
        drop(log);
        let log = RaftLog::open(db.clone()).unwrap();
        assert_eq!(log.snap_last_index(), 3);
        assert_eq!(log.snap_last_term(), 2);
        assert_eq!(log.last_index(), 5);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn compact_idempotent_and_jumps_past_tail_for_snapshot_install() {
        let (db, dir) = temp_db();
        let mut log = RaftLog::open(db.clone()).unwrap();
        for _ in 0..3 {
            let txn = db.begin_write().unwrap();
            log.append_in_txn(&txn, 1, b"x").unwrap();
            txn.commit().unwrap();
        }
        // First compact succeeds.
        let txn = db.begin_write().unwrap();
        log.compact_to_in_txn(&txn, 2, 1).unwrap();
        txn.commit().unwrap();
        // Same compact is a no-op.
        let txn = db.begin_write().unwrap();
        log.compact_to_in_txn(&txn, 2, 1).unwrap();
        txn.commit().unwrap();
        assert_eq!(log.snap_last_index(), 2);
        // Compact past last_index is the snapshot-install case —
        // a far-behind follower receiving a snapshot covering
        // entries it never had. Drop everything we have, jump the
        // snap pointer + last_index to the leader's pointer.
        let txn = db.begin_write().unwrap();
        log.compact_to_in_txn(&txn, 99, 7).unwrap();
        txn.commit().unwrap();
        assert_eq!(log.snap_last_index(), 99);
        assert_eq!(log.snap_last_term(), 7);
        assert_eq!(log.last_index(), 99);
        assert_eq!(log.last_term(), 7);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn meta_round_trips_through_txn() {
        let (db, dir) = temp_db();
        let m = RaftMeta {
            current_term: 7,
            voted_for: Some(0xDEAD),
            commit_index: 42,
            last_applied: 41,
            snap_last_index: 30,
            snap_last_term: 6,
        };
        let txn = db.begin_write().unwrap();
        m.write_in_txn(&txn).unwrap();
        txn.commit().unwrap();
        let loaded = RaftMeta::load(&db).unwrap();
        assert_eq!(loaded, m);
        // Clear voted_for and verify the row is removed.
        let cleared = RaftMeta {
            voted_for: None,
            ..m
        };
        let txn = db.begin_write().unwrap();
        cleared.write_in_txn(&txn).unwrap();
        txn.commit().unwrap();
        let loaded = RaftMeta::load(&db).unwrap();
        assert_eq!(loaded.voted_for, None);
        let _ = std::fs::remove_dir_all(dir);
    }
}
