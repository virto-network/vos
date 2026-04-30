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
/// the tail (`last_index`, `last_term`) to keep append cheap. The
/// cache is recomputed on `open` from the actual table tail.
pub struct RaftLog {
    db: Arc<Database>,
    last_index: u64,
    last_term: u64,
}

impl RaftLog {
    /// Open the log on the given database, recovering the cached tail
    /// from disk. Empty log → `last_index = 0`, `last_term = 0`.
    pub fn open(db: Arc<Database>) -> Result<Self, CommitError> {
        let txn = db.begin_read()?;
        let (last_index, last_term) = match txn.open_table(RAFT_LOG) {
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
        Ok(Self {
            db,
            last_index,
            last_term,
        })
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

    /// Read entries `[start..=end]` in index order. Used by phase 1's
    /// `replay_logs` to walk `1..=last_applied`. Phase 4 will also
    /// use it for AppendEntries replication batches.
    pub fn entries(&self, start: u64, end: u64) -> Result<Vec<LogEntry>, CommitError> {
        if start > end {
            return Ok(Vec::new());
        }
        let txn = self.db.begin_read()?;
        let table = match txn.open_table(RAFT_LOG) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut out = Vec::with_capacity((end - start + 1) as usize);
        for kv in table.range(start..=end)? {
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
    fn meta_round_trips_through_txn() {
        let (db, dir) = temp_db();
        let m = RaftMeta {
            current_term: 7,
            voted_for: Some(0xDEAD),
            commit_index: 42,
            last_applied: 41,
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
