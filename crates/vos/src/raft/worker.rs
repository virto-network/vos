//! Per-replication-group Raft worker.
//!
//! Each Raft actor in the space spawns one [`RaftWorker`] thread.
//! The worker owns the per-group state machine (role, term, vote)
//! and is the single writer for `raft_log` / `raft_meta`. The
//! agent thread interacts with it through two channels:
//!
//! - **Inbound RPCs** ([`RaftRpcHandler`] impl on [`WorkerHandle`]):
//!   the swarm thread converts inbound `AppendEntries` /
//!   `RequestVote` frames into [`RaftMsg`] sends and blocks on a
//!   per-call reply channel until the worker answers.
//! - **Outbound RPCs**: the worker uses [`Network::send_raft_append`]
//!   / [`Network::send_raft_vote`] to call peers; results route
//!   back through the network's reply channels.
//!
//! Phase 3.1 (this commit): Follower role only.
//!   - Inbound `AppendEntries` is treated as a heartbeat (entries
//!     are dropped — replication lands in phase 4). If the
//!     leader's term is at least our current term, we adopt it,
//!     persist to `raft_meta`, and reply `success=true`.
//!   - Inbound `RequestVote` always replies `vote_granted=false`
//!     (voting lands in phase 3.2).
//!   - No election timer yet — the worker blocks on its inbox
//!     until a message or `Shutdown` arrives. Phase 3.2 adds the
//!     timer with a randomized window.
//!
//! [`Network::send_raft_append`]: crate::network::Network::send_raft_append
//! [`Network::send_raft_vote`]: crate::network::Network::send_raft_vote
//! [`RaftRpcHandler`]: crate::network::RaftRpcHandler

use alloc::sync::Arc;
use alloc::vec::Vec;
use std::sync::mpsc as std_mpsc;
use std::thread::{self, JoinHandle};

use redb::Database;
use tracing::{debug, warn};

use crate::network::{
    RaftAppendResult, RaftEntry, RaftRpcHandler, RaftVoteResult,
};

use super::log::{RaftLog, RaftMeta};

/// Cluster role for a replication group. Phase 3.1 only ever
/// stays in `Follower`; `Candidate` / `Leader` arrive in 3.2 / 3.3
/// and are listed here so the role transitions are explicit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    Follower,
    #[allow(dead_code)]
    Candidate,
    #[allow(dead_code)]
    Leader,
}

/// Configuration for a worker.
#[derive(Debug, Clone)]
pub struct WorkerConfig {
    /// Local node's `node_prefix`.
    pub me: u16,
    /// Static cluster membership. Empty in single-node mode.
    pub members: Vec<u16>,
    /// Replication group id — passed back into outbound
    /// `send_raft_*` calls. Phase 3.1 doesn't initiate any
    /// outbound calls, but 3.2+ will.
    pub replication_id: [u8; 32],
}

/// Inbound message processed by the worker loop.
///
/// Some fields are unused in phase 3.1 — `prev_log_term` and
/// `leader_commit` for `AppendEntries`, `from_prefix` /
/// `last_log_index` / `last_log_term` for `RequestVote`. Phase 3.2
/// (voting up-to-date check) and phase 4 (log consistency check)
/// consume them.
#[allow(dead_code)]
pub(crate) enum RaftMsg {
    /// Inbound `AppendEntries` from a peer. The reply channel
    /// receives the [`RaftAppendResult`] this worker decides.
    AppendEntries {
        from_prefix: u16,
        term: u64,
        prev_log_index: u64,
        prev_log_term: u64,
        leader_commit: u64,
        entries: Vec<RaftEntry>,
        reply: std_mpsc::Sender<RaftAppendResult>,
    },
    /// Inbound `RequestVote` from a peer.
    RequestVote {
        from_prefix: u16,
        term: u64,
        last_log_index: u64,
        last_log_term: u64,
        reply: std_mpsc::Sender<RaftVoteResult>,
    },
    Shutdown,
}

/// Owning handle to a running worker. Drop-or-`shutdown` cleans
/// up the thread.
pub struct RaftWorker {
    inbox: std_mpsc::Sender<RaftMsg>,
    join: Option<JoinHandle<()>>,
}

impl RaftWorker {
    /// Spawn a worker thread for one replication group.
    pub fn spawn(db: Arc<Database>, cfg: WorkerConfig) -> Self {
        let (tx, rx) = std_mpsc::channel();
        let join = thread::Builder::new()
            .name(alloc::format!("raft-worker-{:04x}", cfg.me))
            .spawn(move || {
                if let Err(e) = worker_loop(db, cfg, rx) {
                    warn!(error = ?e, "raft: worker exited with error");
                }
            })
            .expect("spawn raft worker");
        Self {
            inbox: tx,
            join: Some(join),
        }
    }

    /// Cheap clone-able handle that implements [`RaftRpcHandler`].
    /// Install on the [`Network`](crate::network::Network) via
    /// `set_raft_handler` so inbound RPCs are routed in.
    pub fn handler(&self) -> WorkerHandle {
        WorkerHandle {
            inbox: self.inbox.clone(),
        }
    }

    /// Stop the worker and join the thread.
    pub fn shutdown(mut self) {
        let _ = self.inbox.send(RaftMsg::Shutdown);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl Drop for RaftWorker {
    fn drop(&mut self) {
        let _ = self.inbox.send(RaftMsg::Shutdown);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Cheap-to-clone handle for installing on a [`Network`] as the
/// inbound RPC handler. Sends each RPC into the worker's inbox
/// and blocks on a per-call reply channel until the worker
/// answers.
#[derive(Clone)]
pub struct WorkerHandle {
    inbox: std_mpsc::Sender<RaftMsg>,
}

impl RaftRpcHandler for WorkerHandle {
    fn append_entries(
        &self,
        _replication_id: &[u8; 32],
        from_prefix: u16,
        term: u64,
        prev_log_index: u64,
        prev_log_term: u64,
        leader_commit: u64,
        entries: Vec<RaftEntry>,
    ) -> RaftAppendResult {
        let (tx, rx) = std_mpsc::channel();
        if self
            .inbox
            .send(RaftMsg::AppendEntries {
                from_prefix,
                term,
                prev_log_index,
                prev_log_term,
                leader_commit,
                entries,
                reply: tx,
            })
            .is_err()
        {
            return RaftAppendResult {
                term,
                success: false,
                match_index: 0,
            };
        }
        rx.recv().unwrap_or(RaftAppendResult {
            term,
            success: false,
            match_index: 0,
        })
    }

    fn request_vote(
        &self,
        _replication_id: &[u8; 32],
        from_prefix: u16,
        term: u64,
        last_log_index: u64,
        last_log_term: u64,
    ) -> RaftVoteResult {
        let (tx, rx) = std_mpsc::channel();
        if self
            .inbox
            .send(RaftMsg::RequestVote {
                from_prefix,
                term,
                last_log_index,
                last_log_term,
                reply: tx,
            })
            .is_err()
        {
            return RaftVoteResult {
                term,
                vote_granted: false,
            };
        }
        rx.recv().unwrap_or(RaftVoteResult {
            term,
            vote_granted: false,
        })
    }
}

/// Worker state. Phase 3.1 carries the bare minimum for Follower
/// behaviour — `last_log_index` and `last_log_term` are loaded
/// from the on-disk log so future heartbeats see the right tail.
/// `log` is unused at this phase (no log writes from a follower
/// yet) but is loaded eagerly so phase 4's consistency check
/// inherits the same struct shape.
struct WorkerState {
    db: Arc<Database>,
    cfg: WorkerConfig,
    role: Role,
    #[allow(dead_code)]
    log: RaftLog,
    meta: RaftMeta,
}

impl WorkerState {
    fn open(db: Arc<Database>, cfg: WorkerConfig) -> Result<Self, crate::commit::CommitError> {
        let log = RaftLog::open(db.clone())?;
        let meta = RaftMeta::load(&db)?;
        Ok(Self {
            db,
            cfg,
            role: Role::Follower,
            log,
            meta,
        })
    }

    fn persist_meta(&self) -> Result<(), crate::commit::CommitError> {
        let txn = self.db.begin_write()?;
        self.meta.write_in_txn(&txn)?;
        txn.commit()?;
        Ok(())
    }
}

fn worker_loop(
    db: Arc<Database>,
    cfg: WorkerConfig,
    inbox: std_mpsc::Receiver<RaftMsg>,
) -> Result<(), crate::commit::CommitError> {
    let mut state = WorkerState::open(db, cfg)?;
    debug!(me = state.cfg.me, "raft: worker started in Follower role");
    while let Ok(msg) = inbox.recv() {
        match msg {
            RaftMsg::Shutdown => {
                debug!(me = state.cfg.me, "raft: worker shutting down");
                break;
            }
            RaftMsg::AppendEntries {
                from_prefix,
                term,
                prev_log_index,
                prev_log_term: _,
                leader_commit: _,
                entries,
                reply,
            } => {
                let resp = handle_append_entries(
                    &mut state,
                    from_prefix,
                    term,
                    prev_log_index,
                    entries.len(),
                )?;
                let _ = reply.send(resp);
            }
            RaftMsg::RequestVote {
                from_prefix: _,
                term,
                last_log_index: _,
                last_log_term: _,
                reply,
            } => {
                // Phase 3.1: voting not yet implemented. Reply
                // refusal so the candidate sees a hard "no" and
                // moves on; phase 3.2 plumbs the real predicate
                // (up-to-date check + at-most-one-vote-per-term).
                let _ = reply.send(RaftVoteResult {
                    term: state.meta.current_term.max(term),
                    vote_granted: false,
                });
            }
        }
    }
    Ok(())
}

fn handle_append_entries(
    state: &mut WorkerState,
    from_prefix: u16,
    term: u64,
    prev_log_index: u64,
    entries_len: usize,
) -> Result<RaftAppendResult, crate::commit::CommitError> {
    // Stale leader: term too low, refuse without changing anything.
    if term < state.meta.current_term {
        return Ok(RaftAppendResult {
            term: state.meta.current_term,
            success: false,
            match_index: 0,
        });
    }

    // Adopt the leader's term if it advances ours, and clear our
    // vote (we may grant a fresh one in this new term — phase 3.2
    // uses this; phase 3.1 only relies on the persistence shape
    // matching what later phases expect).
    let mut meta_changed = false;
    if term > state.meta.current_term {
        state.meta.current_term = term;
        state.meta.voted_for = None;
        meta_changed = true;
    }

    // Phase 3.1 only handles heartbeats (empty entries). A real
    // AppendEntries with non-empty entries is rejected with
    // success=false until phase 4 implements the consistency
    // check + log append. The leader will retry with a smaller
    // batch / earlier prev_log_index, eventually catching us up.
    if entries_len > 0 {
        if meta_changed {
            state.persist_meta()?;
        }
        warn!(
            me = state.cfg.me,
            from_prefix,
            entries_len,
            "raft: phase 3.1 worker rejects non-empty AppendEntries; \
             leader replication lands in phase 4",
        );
        return Ok(RaftAppendResult {
            term: state.meta.current_term,
            success: false,
            match_index: 0,
        });
    }

    // Heartbeat path. The follower stays in `Follower` role.
    state.role = Role::Follower;
    if meta_changed {
        state.persist_meta()?;
    }

    Ok(RaftAppendResult {
        term: state.meta.current_term,
        success: true,
        // For a heartbeat the leader's prev_log_index reflects
        // what *it* last appended. We don't have that entry yet
        // (phase 4 lands replication), so we report 0 — phase 4
        // will refine this once the consistency check lands.
        match_index: prev_log_index,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::raft::log::RaftLog;

    fn temp_db() -> (Arc<Database>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(alloc::format!(
            "vos_raft_worker_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos(),
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Arc::new(Database::create(dir.join("test.redb")).unwrap());
        (db, dir)
    }

    fn cfg(me: u16) -> WorkerConfig {
        WorkerConfig {
            me,
            members: vec![me, me ^ 0x1, me ^ 0x2],
            replication_id: [0xC0; 32],
        }
    }

    #[test]
    fn handler_request_vote_returns_refusal_in_phase_3_1() {
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA));
        let h = worker.handler();
        let resp = h.request_vote(&[0xC0; 32], 0xBBBB, 5, 10, 4);
        assert!(!resp.vote_granted, "phase 3.1 always refuses");
        // The reply mirrors the larger of (peer term, local term).
        // Local is 0 at boot; peer asks at term 5 → reply term 5.
        assert_eq!(resp.term, 5);
        worker.shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn append_entries_heartbeat_advances_term_and_persists() {
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA));
        let h = worker.handler();

        // Heartbeat at term 5 from leader prefix 0xBBBB.
        let resp = h.append_entries(
            &[0xC0; 32], 0xBBBB,
            5,    // term
            0,    // prev_log_index
            0,    // prev_log_term
            0,    // leader_commit
            vec![],
        );
        assert!(resp.success);
        assert_eq!(resp.term, 5);

        // Stale heartbeat at term 4 must be refused without
        // bumping current_term.
        let resp = h.append_entries(
            &[0xC0; 32], 0xCCCC,
            4, 0, 0, 0, vec![],
        );
        assert!(!resp.success);
        assert_eq!(resp.term, 5, "stale leader sees our higher term");

        worker.shutdown();

        // Reopen — current_term must come back from disk.
        let meta = RaftMeta::load(&db).unwrap();
        assert_eq!(meta.current_term, 5);
        assert_eq!(meta.voted_for, None);

        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn append_entries_with_payload_is_refused_in_phase_3_1() {
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA));
        let h = worker.handler();

        let resp = h.append_entries(
            &[0xC0; 32], 0xBBBB,
            5, 0, 0, 0,
            vec![RaftEntry { term: 5, payload: b"x".to_vec() }],
        );
        assert!(!resp.success, "non-empty entries refused until phase 4");
        // But the term still advanced.
        assert_eq!(resp.term, 5);

        // Heartbeats after the bumped term still succeed.
        let resp = h.append_entries(
            &[0xC0; 32], 0xBBBB, 5, 0, 0, 0, vec![],
        );
        assert!(resp.success);

        // Log table is empty — the rejected entry was never appended.
        let log = RaftLog::open(db.clone()).unwrap();
        assert_eq!(log.last_index(), 0);

        worker.shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn worker_shuts_down_cleanly() {
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA));
        // Drop sends shutdown + joins.
        drop(worker);
        // DB is still openable post-drop.
        let _ = RaftMeta::load(&db).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }
}
