//! `RaftCommit` — `CommitStrategy` impl backed by [`RaftLog`].
//!
//! Phase 1.2: single-node mode. Every `commit_with_log` is treated
//! as if `me` is the only voter — append the entry, mark it
//! committed + applied, and persist the post-apply actor state, all
//! in one redb txn. No peers, no leader, no RPCs yet; phase 3
//! introduces those by replacing [`Role::SingleNode`] with a
//! `Multi` variant that owns the cluster state machine and forwards
//! `commit_with_log` requests through a channel to a worker task.
//!
//! The agent thread sees the same [`crate::commit::CommitStrategy`]
//! interface as `LocalCommit` / `CrdtCommit`. On a cold boot,
//! `restore` returns the last persisted state (fast path) or `None`
//! when the state row hasn't been materialized yet — in which case
//! the agent's existing replay loop calls `replay_logs` and feeds
//! each entry's `EffectLog` through the runtime's replay session,
//! exactly like CRDT cold-start does today.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;

use redb::Database;

use crate::commit::{CommitError, CommitStrategy, STATE_KEY, STATE_TABLE};
use crate::effect_log::EffectLog;

use super::log::{RaftLog, RaftMeta};

/// Phase-1 placeholder for cluster state. Acts as if the local node
/// is the only voter, so a `commit_with_log` applies the entry as
/// soon as it lands on disk. Phase 3 adds a `Multi` variant
/// alongside this one and `commit_with_log` dispatches on it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Role {
    /// Self-quorum; commit-and-apply is a single redb txn.
    SingleNode,
}

/// Configuration for a Raft replication group. Phase 1 only uses
/// `me` informationally (it lives in `RaftMeta::voted_for` once
/// elections land); `members` and `election_timeout_ms` are wired
/// at phase 3.
#[derive(Debug, Clone)]
pub struct RaftConfig {
    /// Local node prefix (libp2p-derived `node_prefix`). Identifies
    /// this replica inside the cluster.
    pub me: u16,
    /// Static cluster membership. Empty in phase 1's single-node
    /// mode — a non-empty list is treated as advisory until the
    /// election machinery lands.
    pub members: Vec<u16>,
    /// Randomized election-timeout window (low, high) in milliseconds.
    /// Ignored in phase 1.
    pub election_timeout_ms: (u64, u64),
}

impl Default for RaftConfig {
    fn default() -> Self {
        Self {
            me: 0,
            members: Vec::new(),
            election_timeout_ms: (150, 300),
        }
    }
}

/// `CommitStrategy` backed by a Raft log on redb.
///
/// On a single node this is equivalent to `LocalCommit` plus a
/// monotonically growing log of `EffectLog` payloads — restart
/// rebuilds state by replaying the log. On multi-node clusters
/// (phase 3+) the log becomes the consensus log: only the leader
/// appends, and `commit_with_log` blocks until the entry replicates
/// to a majority and applies locally.
pub struct RaftCommit {
    db: Arc<Database>,
    log: RaftLog,
    meta: RaftMeta,
    /// Cached actor state — same trick `CrdtCommit` uses. Avoids a
    /// redb read every time we want to short-circuit a no-op
    /// commit, and serves as the `restore` fast-path source.
    last_state: Vec<u8>,
    role: Role,
    /// Phase-3 placeholder — set when the cluster worker has been
    /// asked to stop. Phase 1 never reads it; kept here so the
    /// shape of the strategy is stable across phases.
    #[allow(dead_code)]
    shutdown: Arc<AtomicBool>,
    #[allow(dead_code)]
    cfg: RaftConfig,
}

impl RaftCommit {
    /// Open (or create) a Raft-backed strategy at `path`.
    pub fn open(path: &std::path::Path, cfg: RaftConfig) -> Result<Self, CommitError> {
        let db = Arc::new(Database::create(path)?);
        Self::from_db_arc(db, cfg)
    }

    /// Build a `RaftCommit` on a pre-opened `Arc<redb::Database>`.
    /// Mirrors `CrdtCommit::from_db_arc` so a future host that
    /// pre-opens the file (e.g. to share it with a sync ticker)
    /// can do the same here.
    pub fn from_db_arc(db: Arc<Database>, cfg: RaftConfig) -> Result<Self, CommitError> {
        let log = RaftLog::open(db.clone())?;
        let meta = RaftMeta::load(&db)?;
        let last_state = read_state(&db)?.unwrap_or_default();
        Ok(Self {
            db,
            log,
            meta,
            last_state,
            role: Role::SingleNode,
            shutdown: Arc::new(AtomicBool::new(false)),
            cfg,
        })
    }

    /// Borrow the underlying redb database. Useful for tests that
    /// want to introspect the log directly without going through
    /// the strategy.
    pub fn db(&self) -> &Database {
        &self.db
    }

    /// Current `last_applied`. Tests use this to assert log growth
    /// (one entry per state-changing dispatch).
    pub fn last_applied(&self) -> u64 {
        self.meta.last_applied
    }

    /// Append a new log entry, advance `commit_index` and
    /// `last_applied`, and persist the supplied post-apply state —
    /// all in one redb txn. Single-node only; phase 3 routes
    /// through the cluster worker before reaching this point.
    fn append_and_apply_single_node(
        &mut self,
        state: &[u8],
        payload: &[u8],
    ) -> Result<(), CommitError> {
        let term = self.meta.current_term;
        let txn = self.db.begin_write()?;
        let new_index = self.log.append_in_txn(&txn, term, payload)?;
        self.meta.commit_index = new_index;
        self.meta.last_applied = new_index;
        self.meta.write_in_txn(&txn)?;
        {
            let mut state_table = txn.open_table(STATE_TABLE)?;
            state_table.insert(STATE_KEY, state)?;
        }
        txn.commit()?;
        Ok(())
    }
}

impl CommitStrategy for RaftCommit {
    fn restore(&mut self) -> Option<Vec<u8>> {
        if self.last_state.is_empty() {
            None
        } else {
            Some(self.last_state.clone())
        }
    }

    fn commit(&mut self, state: &[u8]) -> Result<(), CommitError> {
        // Plain commit path — used by post-replay state
        // materialization in the agent's cold-start flow. Doesn't
        // append a log entry (no log to attach), only updates the
        // materialized state row, so it's symmetric with what
        // `CrdtCommit::commit` (LocalCommit fall-through) does.
        if state == self.last_state.as_slice() {
            return Ok(());
        }
        let txn = self.db.begin_write()?;
        {
            let mut state_table = txn.open_table(STATE_TABLE)?;
            state_table.insert(STATE_KEY, state)?;
        }
        txn.commit()?;
        self.last_state = state.to_vec();
        Ok(())
    }

    fn commit_with_log(
        &mut self,
        state: &[u8],
        log: &EffectLog,
    ) -> Result<(), CommitError> {
        // Skip-on-unchanged — pure reads must not bloat the log.
        // Same rule `CrdtCommit::commit_with_log` follows; the
        // argument is even stronger here because every Raft entry
        // costs an RTT under multi-node mode (phase 3+).
        if state == self.last_state.as_slice() {
            return Ok(());
        }
        let payload = log.to_bytes();
        match self.role {
            Role::SingleNode => {
                self.append_and_apply_single_node(state, &payload)?;
            }
        }
        self.last_state = state.to_vec();
        Ok(())
    }

    fn replay_logs(&self) -> Result<Vec<EffectLog>, CommitError> {
        if self.meta.last_applied == 0 {
            return Ok(Vec::new());
        }
        // Phase 6 will start this from `snap_last_index + 1`; for
        // now the log is uncompacted so 1..=last_applied is the
        // full causal history.
        let entries = self.log.entries(1, self.meta.last_applied)?;
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            let eff = EffectLog::from_bytes(&e.payload).ok_or_else(|| {
                CommitError::Config(alloc::format!(
                    "raft entry {} has malformed EffectLog payload",
                    e.index,
                ))
            })?;
            out.push(eff);
        }
        Ok(out)
    }

    fn reload(&mut self) -> Result<(), CommitError> {
        // Phase 1 has only one writer (the agent thread), so
        // there's no "background apply" to catch up on. Phase 3
        // wires this to the apply notification from the cluster
        // worker, mirroring CrdtCommit's sync_rx path.
        self.meta = RaftMeta::load(&self.db)?;
        self.log = RaftLog::open(self.db.clone())?;
        self.last_state = read_state(&self.db)?.unwrap_or_default();
        Ok(())
    }

    fn roots(&self) -> Vec<[u8; 32]> {
        // Raft doesn't gossip heads — the cluster has its own
        // heartbeat path (AppendEntries with no entries, phase 4).
        Vec::new()
    }
}

fn read_state(db: &Database) -> Result<Option<Vec<u8>>, CommitError> {
    let txn = db.begin_read()?;
    let table = match txn.open_table(STATE_TABLE) {
        Ok(t) => t,
        Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    Ok(table.get(STATE_KEY)?.map(|v| v.value().to_vec()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_path() -> (std::path::PathBuf, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(alloc::format!(
            "vos_raft_strategy_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        (dir.join("test.redb"), dir)
    }

    fn cfg() -> RaftConfig {
        RaftConfig {
            me: 1,
            ..Default::default()
        }
    }

    #[test]
    fn empty_strategy_returns_no_state_and_no_replay() {
        let (path, dir) = temp_path();
        let mut s = RaftCommit::open(&path, cfg()).unwrap();
        assert_eq!(s.restore(), None);
        assert!(s.replay_logs().unwrap().is_empty());
        assert_eq!(s.last_applied(), 0);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn commit_with_log_appends_entry_and_persists_state() {
        let (path, dir) = temp_path();
        let mut s = RaftCommit::open(&path, cfg()).unwrap();
        let log = EffectLog::for_msg(b"inc 1".to_vec());
        s.commit_with_log(b"state-v1", &log).unwrap();
        assert_eq!(s.last_applied(), 1);
        assert_eq!(s.restore(), Some(b"state-v1".to_vec()));

        // Skip-on-unchanged: same state again must not append.
        s.commit_with_log(b"state-v1", &log).unwrap();
        assert_eq!(s.last_applied(), 1);

        // New state → new entry.
        s.commit_with_log(b"state-v2", &log).unwrap();
        assert_eq!(s.last_applied(), 2);
        assert_eq!(s.restore(), Some(b"state-v2".to_vec()));
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn replay_logs_walks_appended_entries_in_order() {
        let (path, dir) = temp_path();
        let mut s = RaftCommit::open(&path, cfg()).unwrap();
        for i in 0..5u8 {
            let log = EffectLog::for_msg(alloc::vec![i; 4]);
            let state = alloc::vec![i; 8];
            s.commit_with_log(&state, &log).unwrap();
        }
        let logs = s.replay_logs().unwrap();
        assert_eq!(logs.len(), 5);
        for (i, log) in logs.iter().enumerate() {
            assert_eq!(log.msg, alloc::vec![i as u8; 4]);
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn restart_replays_log_to_recover_state() {
        let (path, dir) = temp_path();
        // First boot — commit a few entries.
        {
            let mut s = RaftCommit::open(&path, cfg()).unwrap();
            for i in 0..3u8 {
                s.commit_with_log(
                    &alloc::vec![i; 8],
                    &EffectLog::for_msg(alloc::vec![i; 4]),
                )
                .unwrap();
            }
            assert_eq!(s.last_applied(), 3);
        }
        // Second boot — same path. last_state must come back from
        // disk via `restore`, replay_logs must return the same
        // three entries.
        let mut s = RaftCommit::open(&path, cfg()).unwrap();
        assert_eq!(s.restore(), Some(alloc::vec![2u8; 8]));
        assert_eq!(s.last_applied(), 3);
        assert_eq!(s.replay_logs().unwrap().len(), 3);
        let _ = std::fs::remove_dir_all(dir);
    }
}
