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
// The multi-node path (the worker, propose-and-wait) needs libp2p; only
// the `network` feature pulls it in. Single-node `RaftCommit` stays
// available under `storage` alone, so these imports — and every
// `Role::Multi` site below — are gated on `network` to keep the
// storage-only build (and the public single-node API) compiling.
#[cfg(feature = "network")]
use std::sync::mpsc as std_mpsc;
#[cfg(feature = "network")]
use std::time::Duration;

use redb::Database;

use crate::commit::{
    AgentDelta, CommitError, CommitReceipt, CommitStrategy, KV_TABLE, STATE_KEY, STATE_TABLE,
    split_delta,
};
use crate::effect_log::EffectLog;

use super::log::{RaftLog, RaftMeta};
#[cfg(feature = "network")]
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
    #[cfg(feature = "network")]
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
    #[cfg(feature = "network")]
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
    #[cfg(feature = "network")]
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
    /// `last_applied`, and persist the post-apply delta rows —
    /// all in one redb txn. Single-node only; multi-mode routes
    /// through the cluster worker before reaching this point.
    fn append_and_apply_single_node(
        &mut self,
        state: Option<&[u8]>,
        rest: &[(&[u8], &[u8])],
        payload: &[u8],
    ) -> Result<(), CommitError> {
        let term = self.meta.current_term;
        let txn = self.db.begin_write()?;
        // Wrap the application payload as `EntryKind::Data` so the
        // single-node and multi-node on-disk formats agree —
        // `RaftCommit::replay_logs` decodes the same kind-tag
        // shape on both paths.
        let kind = vos_raft::EntryKind::Data {
            payload: payload.to_vec(),
        };
        let on_disk = super::redb_storage::encode_entry_kind(&kind);
        let new_index = self.log.append_in_txn(&txn, term, &on_disk)?;
        self.meta.commit_index = new_index;
        self.meta.last_applied = new_index;
        self.meta.write_in_txn(&txn)?;
        {
            if let Some(state) = state {
                let mut state_table = txn.open_table(STATE_TABLE)?;
                state_table.insert(STATE_KEY, state)?;
            }
            if !rest.is_empty() {
                let mut kv = txn.open_table(KV_TABLE)?;
                for (key, value) in rest {
                    kv.insert(*key, *value)?;
                }
            }
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

    fn commit(&mut self, delta: &AgentDelta<'_>) -> Result<CommitReceipt, CommitError> {
        let (state, rest) = split_delta(delta);
        let state_changed = state.is_some_and(|s| s != self.last_state.as_slice());

        let Some(log) = delta.log else {
            // Log-less commit — post-replay state materialization in
            // the agent's cold-start flow AND the follower's
            // apply-on-commit-advance path. Doesn't append a log entry
            // (no log to attach), only updates the materialized rows +
            // advances `last_applied` to match the worker's
            // `commit_index` (everything up to commit_index has now
            // been applied to produce this delta).
            if !state_changed && rest.is_empty() {
                return Ok(CommitReceipt {
                    node_appended: false,
                });
            }
            // Reload meta to learn the worker's current commit_index.
            // The agent calls this after running the replay loop
            // up through every committed log entry, so commit_index
            // is the exact point our `last_applied` should reach.
            self.meta = RaftMeta::load(&self.db)?;
            let new_last_applied = self.meta.commit_index;
            let txn = self.db.begin_write()?;
            {
                if state_changed
                    && let Some(state) = state
                {
                    let mut state_table = txn.open_table(STATE_TABLE)?;
                    state_table.insert(STATE_KEY, state)?;
                }
                if !rest.is_empty() {
                    let mut kv = txn.open_table(KV_TABLE)?;
                    for (key, value) in &rest {
                        kv.insert(*key, *value)?;
                    }
                }
            }
            if new_last_applied > self.meta.last_applied {
                self.meta.last_applied = new_last_applied;
                // Write ONLY META_LAST_APPLIED, not the full
                // RaftMeta — we loaded `self.meta` earlier; the
                // worker may have advanced `commit_index` /
                // `current_term` since, and writing the full row
                // would clobber those advances with our stale
                // snapshot.
                self.meta.write_host_fields_in_txn(&txn)?;
            }
            txn.commit()?;
            if state_changed
                && let Some(state) = state
            {
                self.last_state = state.to_vec();
            }
            return Ok(CommitReceipt {
                node_appended: false,
            });
        };

        // Durable-node rule, raft flavor: pure reads must not bloat the
        // log — even stronger here than for CRDT because every entry
        // costs an RTT under multi-node mode. An effect-bearing v3
        // dispatch appends even when state is unchanged; v2 deltas fall
        // back to value comparison.
        if !state_changed && !delta.effect_bearing && rest.is_empty() {
            return Ok(CommitReceipt {
                node_appended: false,
            });
        }
        let state_write = state_changed.then_some(state).flatten();
        let payload = log.to_bytes();
        match &self.role {
            Role::SingleNode => {
                self.append_and_apply_single_node(state_write, &rest, &payload)?;
            }
            #[cfg(feature = "network")]
            Role::Multi { worker, apply_rx } => {
                let propose_timeout = Duration::from_millis(self.cfg.propose_timeout_ms);
                let handle = worker.handler();
                let idx = handle.propose(payload).map_err(|e| match e {
                    ProposeError::NotLeader => CommitError::Config(
                        "raft commit: this replica is not the leader".into(),
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
                            "raft commit: propose at index {idx} did not \
                             reach a quorum within {} ms",
                            self.cfg.propose_timeout_ms,
                        )));
                    }
                    match apply_rx.recv_timeout(remaining) {
                        Ok(committed) if committed >= idx => break,
                        Ok(_) => continue, // earlier index — keep waiting
                        Err(std_mpsc::RecvTimeoutError::Timeout) => {
                            return Err(CommitError::Config(alloc::format!(
                                "raft commit: timeout waiting for index {idx}",
                            )));
                        }
                        Err(std_mpsc::RecvTimeoutError::Disconnected) => {
                            return Err(CommitError::Config(
                                "raft commit: worker apply channel closed".into(),
                            ));
                        }
                    }
                }
                // Quorum-committed. Persist the delta rows +
                // bump `last_applied` in our own txn (the worker
                // owns log + commit_index + voted_for + snap
                // pointer; the host owns state + last_applied).
                // Atomic write so a crash here either rolls
                // back the apply entirely or commits the rows and
                // last_applied together. `write_host_fields_in_txn`
                // touches ONLY `META_LAST_APPLIED` so we don't
                // race the worker's concurrent writes to the
                // worker-owned scalars.
                self.meta = RaftMeta::load(&self.db)?;
                self.meta.last_applied = self.meta.last_applied.max(idx);
                let txn = self.db.begin_write()?;
                {
                    if let Some(state) = state_write {
                        let mut state_table = txn.open_table(STATE_TABLE)?;
                        state_table.insert(STATE_KEY, state)?;
                    }
                    if !rest.is_empty() {
                        let mut kv = txn.open_table(KV_TABLE)?;
                        for (key, value) in &rest {
                            kv.insert(*key, *value)?;
                        }
                    }
                }
                self.meta.write_host_fields_in_txn(&txn)?;
                txn.commit()?;
            }
        }
        if let Some(state) = state_write {
            self.last_state = state.to_vec();
        }
        Ok(CommitReceipt {
            node_appended: true,
        })
    }

    fn restore_writes(&self) -> Result<Vec<(Vec<u8>, Vec<u8>)>, CommitError> {
        crate::commit::read_kv_rows(&self.db)
    }

    fn replay_logs(&self) -> Result<Vec<EffectLog>, CommitError> {
        // Returns every committed entry past the snap pointer.
        // The runtime is responsible for idempotent replay
        // semantics — `EffectLog::dispatch` runs as a "replay
        // session" that rebuilds state from scratch. Bounding
        // by `commit_index` (not `last_applied`) is what makes
        // the follower path work: a follower's worker advances
        // commit_index via heartbeats, the agent runs replay,
        // calls `commit()` which bumps last_applied.
        if self.meta.commit_index == 0 {
            return Ok(Vec::new());
        }
        let start = self.meta.snap_last_index.saturating_add(1);
        let end = self.meta.commit_index;
        if start > end {
            return Ok(Vec::new());
        }
        let entries = self.log.entries(start, end)?;
        let mut out = Vec::with_capacity(entries.len());
        for e in entries {
            // Each row carries a leading kind byte that distinguishes
            // application data from membership transitions. The
            // host's apply path is only interested in `Data`
            // entries; `ConfigChange` entries are consumed by the
            // worker's quorum logic and surface to the host as
            // commit_index advances without a corresponding dispatch.
            let body = match super::redb_storage::decode_entry_kind(&e.payload) {
                Ok(vos_raft::EntryKind::Data { payload }) => payload,
                Ok(vos_raft::EntryKind::ConfigChange { .. }) => continue,
                Ok(_) => continue, // future kinds — host can't apply
                Err(e) => return Err(e),
            };
            // The vos-raft worker appends an empty-payload `Data`
            // entry on leader promotion (Ongaro §6.4) so a new
            // leader's term has at least one entry to commit
            // before any read_index can resolve. The host has no
            // dispatch to replay for it — skip cleanly instead of
            // failing on `EffectLog::from_bytes(&[])`.
            if body.is_empty() {
                continue;
            }
            let eff = EffectLog::from_bytes(&body).ok_or_else(|| {
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

    fn needs_sync_reload(&self) -> bool {
        // The worker advances `commit_index` on disk out-of-band — its own
        // quorum matches AND a follower receiving a higher `leader_commit` from
        // a heartbeat — while the host owns `last_applied`, bumped only when WE
        // apply an entry (`commit_with_log` on our own proposal, or `commit()`
        // after the follower replay). So there is something to fold in iff the
        // committed frontier sits ahead of what we've applied. After our own
        // commit `last_applied == commit_index`, so this is false and the agent
        // skips the soft-restart — which would otherwise replay the whole log on
        // every single commit (O(n) per commit ⇒ O(n²)) and stall a
        // continuously-committing actor, the chronos clock being the first to
        // hit it. A follower receiving the leader's entries advances
        // commit_index past last_applied, so it still reloads and converges.
        let commit_index = RaftMeta::load(&self.db)
            .map(|m| m.commit_index)
            .unwrap_or(self.meta.commit_index);
        commit_index > self.meta.last_applied
    }

    fn is_writable(&self) -> bool {
        match &self.role {
            // Single-node mode is always writable — the agent
            // is the only participant, no leadership to lose.
            Role::SingleNode => true,
            // Multi mode: writable iff this replica is currently
            // the leader. Lock-free atomic read — doesn't bounce
            // through the worker's mpsc inbox.
            #[cfg(feature = "network")]
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

    #[cfg(feature = "network")]
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

    #[cfg(feature = "network")]
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
        // tick (10-30ms randomized). Generous deadline because
        // `futures-timer` (the std-clock timer) gets sluggish under
        // heavy `cargo test` parallelism — the production runtime
        // doesn't see this contention.
        let h = worker.handler();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        loop {
            if let Some(snap) = h.snapshot() {
                if snap.role == super::super::worker::Role::Leader {
                    break;
                }
            }
            assert!(std::time::Instant::now() < deadline, "no leadership");
            std::thread::sleep(std::time::Duration::from_millis(5));
        }

        let mut s = RaftCommit::from_worker(db.clone(), cfg, worker, apply_rx).unwrap();

        // First propose: state=v1, log=msg1. Index 1 is the
        // vos-raft leader-promotion no-op (Ongaro §6.4); the
        // application propose lands at index 2.
        let log = EffectLog::for_msg(b"first".to_vec());
        s.commit_with_log(b"state-v1", &log).unwrap();
        assert_eq!(s.restore(), Some(b"state-v1".to_vec()));
        assert_eq!(s.last_applied(), 2);

        // Idempotent skip on unchanged state — no new log entry.
        s.commit_with_log(b"state-v1", &log).unwrap();
        assert_eq!(s.last_applied(), 2);

        // Second propose: state=v2.
        s.commit_with_log(b"state-v2", &EffectLog::for_msg(b"second".to_vec()))
            .unwrap();
        assert_eq!(s.restore(), Some(b"state-v2".to_vec()));
        assert_eq!(s.last_applied(), 3);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn restart_replays_log_to_recover_state() {
        let (path, dir) = temp_path();
        // First boot — commit a few entries.
        {
            let mut s = RaftCommit::open(&path, cfg()).unwrap();
            for i in 0..3u8 {
                s.commit_with_log(&alloc::vec![i; 8], &EffectLog::for_msg(alloc::vec![i; 4]))
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
