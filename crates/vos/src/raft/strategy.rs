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
use std::sync::mpsc as std_mpsc;
use std::time::Duration;

use redb::Database;

use crate::commit::{CommitError, CommitStrategy, STATE_KEY, STATE_TABLE};
use crate::effect_log::EffectLog;

use super::log::{RaftLog, RaftMeta};
use super::worker::{ProposeError, RaftWorker, WorkerHandle};

/// Cluster role for a `RaftCommit`. Single-node mode is "self
/// quorum is the only voter" — every commit appends + applies in
/// one txn, no peers involved. Multi-node mode owns a
/// [`RaftWorker`] and routes `commit_with_log` through propose +
/// quorum-wait.
enum Role {
    /// Self-quorum; commit-and-apply is a single redb txn.
    SingleNode,
    /// Cluster mode. Owns the worker thread and an apply receiver
    /// it drains in `commit_with_log` until the proposed entry's
    /// commit_index is reached.
    Multi {
        worker: RaftWorker,
        /// Receives every new `commit_index` value the worker
        /// observes (own quorum advance OR follower receiving a
        /// heartbeat with a higher leader_commit). Exclusive to
        /// this RaftCommit instance.
        apply_rx: std_mpsc::Receiver<u64>,
    },
}

/// Configuration for a Raft replication group. Phase 1 only uses
/// `me` informationally (it lives in `RaftMeta::voted_for` once
/// elections land); `members` and `election_timeout_ms` are wired
/// at phase 3, `heartbeat_interval_ms` at phase 3.3.
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
    /// Leader heartbeat interval in milliseconds. Should be
    /// substantially smaller than `election_timeout_ms.0`.
    pub heartbeat_interval_ms: u64,
    /// Replication group ID — typically `blake2b(blob || actor_name)`.
    /// All cluster members of the same Raft group share this. Used
    /// for outbound RPC routing and as the gossipsub topic key.
    pub replication_id: [u8; 32],
    /// Hard cap on how long `commit_with_log` waits for an
    /// in-flight propose to commit before failing with
    /// `CommitError::Config("propose timed out")`. Defaults to 5 s.
    pub propose_timeout_ms: u64,
}

impl Default for RaftConfig {
    fn default() -> Self {
        Self {
            me: 0,
            members: Vec::new(),
            election_timeout_ms: (150, 300),
            heartbeat_interval_ms: 50,
            replication_id: [0u8; 32],
            propose_timeout_ms: 5_000,
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
    /// Open (or create) a Raft-backed strategy at `path`. Returns
    /// a `SingleNode` strategy — every commit is self-quorumed.
    /// Use [`open_multi`](Self::open_multi) for a real cluster.
    pub fn open(path: &std::path::Path, cfg: RaftConfig) -> Result<Self, CommitError> {
        let db = Arc::new(Database::create(path)?);
        Self::from_db_arc(db, cfg)
    }

    /// Build a single-node `RaftCommit` on a pre-opened
    /// `Arc<redb::Database>`. Mirrors `CrdtCommit::from_db_arc`
    /// so a future host that pre-opens the file (e.g. to share it
    /// with a sync ticker) can do the same here.
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

    /// Build a multi-node `RaftCommit` that owns a [`RaftWorker`].
    /// `commit_with_log` proposes through the worker, blocks until
    /// the entry is committed by quorum, then persists state.
    ///
    /// `apply_rx` receives every commit-index advance the worker
    /// observes (own quorum match OR follower receiving a higher
    /// `leader_commit` from a heartbeat). The receiver should be
    /// the matched half of the `Sender` handed to `RaftWorker::spawn`.
    pub fn from_worker(
        db: Arc<Database>,
        cfg: RaftConfig,
        worker: RaftWorker,
        apply_rx: std_mpsc::Receiver<u64>,
    ) -> Result<Self, CommitError> {
        let log = RaftLog::open(db.clone())?;
        let meta = RaftMeta::load(&db)?;
        let last_state = read_state(&db)?.unwrap_or_default();
        Ok(Self {
            db,
            log,
            meta,
            last_state,
            role: Role::Multi { worker, apply_rx },
            shutdown: Arc::new(AtomicBool::new(false)),
            cfg,
        })
    }

    /// Read-only access to the worker handle when in `Multi` mode.
    /// Useful for installing it as the `RaftRpcHandler` on a
    /// network. Returns `None` for `SingleNode`.
    pub fn worker_handle(&self) -> Option<WorkerHandle> {
        match &self.role {
            Role::Multi { worker, .. } => Some(worker.handler()),
            Role::SingleNode => None,
        }
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
        // Even stronger here than for CRDT because every Raft
        // entry costs an RTT under multi-node mode.
        if state == self.last_state.as_slice() {
            return Ok(());
        }
        let payload = log.to_bytes();
        let propose_timeout = Duration::from_millis(self.cfg.propose_timeout_ms);
        match &self.role {
            Role::SingleNode => {
                self.append_and_apply_single_node(state, &payload)?;
            }
            Role::Multi { worker, apply_rx } => {
                let handle = worker.handler();
                let idx = handle.propose(payload).map_err(|e| match e {
                    ProposeError::NotLeader => CommitError::Config(
                        "raft commit_with_log: this replica is not the leader".into(),
                    ),
                    ProposeError::Storage(inner) => inner,
                })?;
                // Drain apply notifications until the worker
                // reports commit_index ≥ idx. In flight at this
                // moment: the worker is shipping AppendEntries to
                // followers and tallying their match_index; once
                // a quorum reaches `idx`, `try_advance_commit_index`
                // fires the notifier.
                let deadline = std::time::Instant::now() + propose_timeout;
                loop {
                    let remaining = deadline.saturating_duration_since(std::time::Instant::now());
                    if remaining.is_zero() {
                        return Err(CommitError::Config(alloc::format!(
                            "raft commit_with_log: propose at index {idx} did not \
                             reach a quorum within {} ms",
                            self.cfg.propose_timeout_ms,
                        )));
                    }
                    match apply_rx.recv_timeout(remaining) {
                        Ok(committed) if committed >= idx => break,
                        Ok(_) => continue, // earlier index — keep waiting
                        Err(std_mpsc::RecvTimeoutError::Timeout) => {
                            return Err(CommitError::Config(alloc::format!(
                                "raft commit_with_log: timeout waiting for index {idx}",
                            )));
                        }
                        Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                            return Err(CommitError::Config(
                                "raft commit_with_log: worker apply channel closed".into(),
                            ));
                        }
                    }
                }
                // Quorum-committed. Persist the state row in our
                // own txn (worker owns log + meta; agent owns
                // state). On crash between this txn and the
                // worker's commit_index advance, restart will see
                // commit_index ≥ idx and replay the log to
                // rebuild state — same shape used for cold start.
                let txn = self.db.begin_write()?;
                {
                    let mut state_table = txn.open_table(STATE_TABLE)?;
                    state_table.insert(STATE_KEY, state)?;
                }
                txn.commit()?;
                // Refresh our cached meta from disk so
                // `last_applied()` reflects the worker's advance.
                self.meta = RaftMeta::load(&self.db)?;
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

    fn is_writable(&self) -> bool {
        match &self.role {
            // Single-node mode is always writable — the agent
            // is the only participant, no leadership to lose.
            Role::SingleNode => true,
            // Multi mode: writable iff this replica is currently
            // the leader. Lock-free atomic read — doesn't bounce
            // through the worker's mpsc inbox.
            Role::Multi { worker, .. } => worker.role() == super::worker::Role::Leader,
        }
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

    fn cfg_multi(me: u16, members: Vec<u16>) -> RaftConfig {
        RaftConfig {
            me,
            members,
            // Tiny timeouts so the single-member self-quorum
            // election fires before the test's propose call.
            election_timeout_ms: (10, 30),
            heartbeat_interval_ms: 500,
            replication_id: [0xC0; 32],
            propose_timeout_ms: 2_000,
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
    fn multi_mode_solo_cluster_propose_and_persist() {
        // Single-member "cluster": the worker self-elects in
        // milliseconds (its self-vote is the quorum), then a
        // commit_with_log proposes through it, blocks on the
        // apply notification, and persists state. This is the
        // tightest end-to-end test of the propose-and-wait path
        // without needing a real network.
        use super::super::worker::{RaftWorker, WorkerConfig};

        let (path, dir) = temp_path();
        let db = Arc::new(Database::create(&path).unwrap());
        let cfg = cfg_multi(0xAAAA, vec![0xAAAA]);

        let (apply_tx, apply_rx) = std_mpsc::channel::<u64>();
        let worker = RaftWorker::spawn(
            db.clone(),
            WorkerConfig {
                me: cfg.me,
                members: cfg.members.clone(),
                replication_id: cfg.replication_id,
                election_timeout_ms: cfg.election_timeout_ms,
                heartbeat_interval_ms: cfg.heartbeat_interval_ms,
            },
            None, // no network — single-node self-quorum doesn't need one
            Some(apply_tx),
        );

        // Wait for the self-elected leadership before proposing.
        // The single-member quorum fires on the first election
        // tick (10-30ms randomized).
        let h = worker.handler();
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(500);
        loop {
            if let Some(snap) = h.snapshot() {
                if snap.role == super::super::worker::Role::Leader { break; }
            }
            assert!(std::time::Instant::now() < deadline, "no leadership");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let mut s = RaftCommit::from_worker(db.clone(), cfg, worker, apply_rx).unwrap();

        // First propose: state=v1, log=msg1.
        let log = EffectLog::for_msg(b"first".to_vec());
        s.commit_with_log(b"state-v1", &log).unwrap();
        assert_eq!(s.restore(), Some(b"state-v1".to_vec()));
        assert_eq!(s.last_applied(), 1);

        // Idempotent skip on unchanged state — no new log entry.
        s.commit_with_log(b"state-v1", &log).unwrap();
        assert_eq!(s.last_applied(), 1);

        // Second propose: state=v2.
        s.commit_with_log(b"state-v2", &EffectLog::for_msg(b"second".to_vec())).unwrap();
        assert_eq!(s.restore(), Some(b"state-v2".to_vec()));
        assert_eq!(s.last_applied(), 2);

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
