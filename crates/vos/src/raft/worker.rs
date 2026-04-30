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
use std::time::{Duration, Instant};

use redb::Database;
use tracing::{debug, warn};

use crate::network::{
    Network, RaftAppendResult, RaftEntry, RaftRpcHandler, RaftVoteResult,
};

use super::log::{RaftLog, RaftMeta};

/// Hard upper bound on how long a single outbound vote helper
/// thread waits for a peer's reply before giving up. The election
/// timeout will fire long before this — the cap exists only so a
/// peer that drops a request without ever replying doesn't leak a
/// helper thread for the lifetime of the worker.
const VOTE_RPC_TIMEOUT: Duration = Duration::from_secs(2);

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
    /// Static cluster membership. Empty / single-element disables
    /// elections (single-node mode stays in `Follower` forever
    /// since there's no quorum to win).
    pub members: Vec<u16>,
    /// Replication group id — used for outbound `send_raft_*`
    /// calls and for matching inbound RPCs.
    pub replication_id: [u8; 32],
    /// Randomized election-timeout window (low, high) in
    /// milliseconds. The actual timeout for each Follower /
    /// Candidate cycle is drawn uniformly from this range. Tests
    /// shrink it to ~50ms; production defaults sit at 150-300ms.
    pub election_timeout_ms: (u64, u64),
}

/// Inbound message processed by the worker loop.
///
/// Some fields are unused in this phase — `prev_log_term` and
/// `leader_commit` for `AppendEntries` — and consumed by phase 4
/// (log consistency check + commit advance).
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
    /// Drained by the worker after every outbound `send_raft_vote`
    /// helper thread receives the peer's reply (or times out
    /// trying). Carries the answer back into the worker so the
    /// tally happens on the worker's single-threaded inbox.
    VoteResponse {
        from_prefix: u16,
        term: u64,
        vote_granted: bool,
    },
    /// Test/diagnostic: snapshot the worker's role + term.
    QueryState {
        reply: std_mpsc::Sender<WorkerSnapshot>,
    },
    Shutdown,
}

/// Diagnostic snapshot of a worker's state. Returned by
/// [`WorkerHandle::snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerSnapshot {
    pub role: Role,
    pub current_term: u64,
    pub voted_for: Option<u16>,
    pub last_log_index: u64,
}

/// Owning handle to a running worker. Drop-or-`shutdown` cleans
/// up the thread.
pub struct RaftWorker {
    inbox: std_mpsc::Sender<RaftMsg>,
    join: Option<JoinHandle<()>>,
}

impl RaftWorker {
    /// Spawn a worker thread for one replication group. `network`
    /// is `None` for unit tests and single-node mode (no outbound
    /// RPCs); a `Some(_)` enables real elections by giving the
    /// worker a way to call peers.
    pub fn spawn(
        db: Arc<Database>,
        cfg: WorkerConfig,
        network: Option<Arc<Network>>,
    ) -> Self {
        let (tx, rx) = std_mpsc::channel();
        let inbox_tx = tx.clone();
        let join = thread::Builder::new()
            .name(alloc::format!("raft-worker-{:04x}", cfg.me))
            .spawn(move || {
                if let Err(e) = worker_loop(db, cfg, network, rx, inbox_tx) {
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

impl WorkerHandle {
    /// Test / diagnostic — block briefly waiting for the worker
    /// to send back a snapshot of its current state. Returns
    /// `None` if the worker is shut down or busy beyond the
    /// internal deadline.
    pub fn snapshot(&self) -> Option<WorkerSnapshot> {
        let (tx, rx) = std_mpsc::channel();
        self.inbox.send(RaftMsg::QueryState { reply: tx }).ok()?;
        rx.recv_timeout(Duration::from_millis(500)).ok()
    }
}

/// Worker state. Owns the per-group state machine + the
/// in-memory tally for an in-flight election.
struct WorkerState {
    db: Arc<Database>,
    cfg: WorkerConfig,
    network: Option<Arc<Network>>,
    /// Sender clone of the worker's own inbox. Used by helper
    /// threads spawned for outbound `RequestVote` to deliver
    /// `VoteResponse` messages back into the single-threaded
    /// state machine.
    inbox_tx: std_mpsc::Sender<RaftMsg>,
    role: Role,
    log: RaftLog,
    meta: RaftMeta,
    /// Next election timeout. `Instant::now() >= deadline` triggers
    /// a Follower → Candidate transition. Followers refresh this
    /// on every accepted heartbeat / granted vote; candidates
    /// refresh it when starting an election; leaders push it far
    /// into the future (phase 3.3 replaces this with a heartbeat
    /// tick).
    election_deadline: Instant,
    /// Set of voters that have granted us a vote *in this term*.
    /// Includes ourselves the moment we become Candidate.
    votes_received: alloc::collections::BTreeSet<u16>,
}

impl WorkerState {
    fn open(
        db: Arc<Database>,
        cfg: WorkerConfig,
        network: Option<Arc<Network>>,
        inbox_tx: std_mpsc::Sender<RaftMsg>,
    ) -> Result<Self, crate::commit::CommitError> {
        let log = RaftLog::open(db.clone())?;
        let meta = RaftMeta::load(&db)?;
        let mut s = Self {
            db,
            cfg,
            network,
            inbox_tx,
            role: Role::Follower,
            log,
            meta,
            election_deadline: Instant::now(),
            votes_received: alloc::collections::BTreeSet::new(),
        };
        s.reset_election_timer();
        Ok(s)
    }

    fn persist_meta(&self) -> Result<(), crate::commit::CommitError> {
        let txn = self.db.begin_write()?;
        self.meta.write_in_txn(&txn)?;
        txn.commit()?;
        Ok(())
    }

    fn reset_election_timer(&mut self) {
        let (lo, hi) = self.cfg.election_timeout_ms;
        let span = (hi.saturating_sub(lo)).max(1);
        // Crude per-call PRNG seeded from the system clock + the
        // worker's prefix; good enough to scatter timeouts across
        // peers so they don't all time out simultaneously.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0);
        let jitter = (nanos.wrapping_mul(0x9E3779B97F4A7C15)
            ^ self.cfg.me as u64
            ^ self.meta.current_term)
            % span;
        let timeout = Duration::from_millis(lo + jitter);
        self.election_deadline = Instant::now() + timeout;
    }

    fn quorum(&self) -> usize {
        // Majority of total members — the candidate counts itself,
        // so for 3 members we need 2 votes (the candidate + one
        // peer); for 5 members, 3 votes; etc. Single-member
        // configurations would need 1 vote total which the
        // candidate's self-vote already provides, so they'd
        // immediately become Leader; phase 3.2 tests use ≥3.
        self.cfg.members.len() / 2 + 1
    }
}

fn worker_loop(
    db: Arc<Database>,
    cfg: WorkerConfig,
    network: Option<Arc<Network>>,
    inbox: std_mpsc::Receiver<RaftMsg>,
    inbox_tx: std_mpsc::Sender<RaftMsg>,
) -> Result<(), crate::commit::CommitError> {
    let mut state = WorkerState::open(db, cfg, network, inbox_tx)?;
    debug!(me = state.cfg.me, "raft: worker started in Follower role");

    loop {
        let now = Instant::now();
        let timeout = state.election_deadline.saturating_duration_since(now);
        match inbox.recv_timeout(timeout) {
            Ok(RaftMsg::Shutdown) => {
                debug!(me = state.cfg.me, "raft: worker shutting down");
                break;
            }
            Ok(RaftMsg::AppendEntries {
                from_prefix,
                term,
                prev_log_index,
                prev_log_term: _,
                leader_commit: _,
                entries,
                reply,
            }) => {
                let resp = handle_append_entries(
                    &mut state,
                    from_prefix,
                    term,
                    prev_log_index,
                    entries.len(),
                )?;
                let _ = reply.send(resp);
            }
            Ok(RaftMsg::RequestVote {
                from_prefix,
                term,
                last_log_index,
                last_log_term,
                reply,
            }) => {
                let resp = handle_request_vote(
                    &mut state,
                    from_prefix,
                    term,
                    last_log_index,
                    last_log_term,
                )?;
                let _ = reply.send(resp);
            }
            Ok(RaftMsg::VoteResponse {
                from_prefix,
                term,
                vote_granted,
            }) => {
                handle_vote_response(&mut state, from_prefix, term, vote_granted)?;
            }
            Ok(RaftMsg::QueryState { reply }) => {
                let _ = reply.send(WorkerSnapshot {
                    role: state.role,
                    current_term: state.meta.current_term,
                    voted_for: state.meta.voted_for,
                    last_log_index: state.log.last_index(),
                });
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => {
                if matches!(state.role, Role::Follower | Role::Candidate) {
                    start_election(&mut state)?;
                } else {
                    // Leader: phase 3.2 doesn't run heartbeats yet,
                    // so push the deadline out so we keep handling
                    // inbound traffic without re-triggering elections.
                    // Phase 3.3 replaces this with a real heartbeat
                    // tick.
                    state.election_deadline = Instant::now() + Duration::from_secs(60);
                }
            }
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
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

    let mut meta_changed = false;
    if term > state.meta.current_term {
        state.meta.current_term = term;
        state.meta.voted_for = None;
        meta_changed = true;
    }
    // Any AppendEntries from a current-term leader is a
    // legitimate signal to step down to Follower (whether we're
    // already a Follower or a stale Candidate / Leader at a
    // lower term). The role transition is the leader's
    // authority asserting itself.
    state.role = Role::Follower;
    state.votes_received.clear();
    state.reset_election_timer();

    // Phase 3.2 still only handles heartbeats (empty entries).
    // Real replication lands in phase 4.
    if entries_len > 0 {
        if meta_changed {
            state.persist_meta()?;
        }
        warn!(
            me = state.cfg.me,
            from_prefix,
            entries_len,
            "raft: phase 3.2 worker rejects non-empty AppendEntries; \
             leader replication lands in phase 4",
        );
        return Ok(RaftAppendResult {
            term: state.meta.current_term,
            success: false,
            match_index: 0,
        });
    }

    if meta_changed {
        state.persist_meta()?;
    }

    Ok(RaftAppendResult {
        term: state.meta.current_term,
        success: true,
        match_index: prev_log_index,
    })
}

fn handle_request_vote(
    state: &mut WorkerState,
    from_prefix: u16,
    term: u64,
    last_log_index: u64,
    last_log_term: u64,
) -> Result<RaftVoteResult, crate::commit::CommitError> {
    // Stale candidate term — refuse, advertise our higher term
    // so they can step down.
    if term < state.meta.current_term {
        return Ok(RaftVoteResult {
            term: state.meta.current_term,
            vote_granted: false,
        });
    }

    let mut meta_changed = false;
    if term > state.meta.current_term {
        state.meta.current_term = term;
        state.meta.voted_for = None;
        state.role = Role::Follower;
        state.votes_received.clear();
        meta_changed = true;
    }

    // Up-to-date check: candidate's log must be at least as new
    // as ours. Either the last term is strictly higher, or the
    // last term matches and the index is at least as high.
    let our_last_term = state.log.last_term();
    let our_last_index = state.log.last_index();
    let candidate_up_to_date = (last_log_term > our_last_term)
        || (last_log_term == our_last_term && last_log_index >= our_last_index);

    let already_voted_otherwise = state
        .meta
        .voted_for
        .is_some_and(|v| v != from_prefix);

    let granted = !already_voted_otherwise && candidate_up_to_date;

    if granted {
        state.meta.voted_for = Some(from_prefix);
        state.reset_election_timer();
        meta_changed = true;
    }

    if meta_changed {
        state.persist_meta()?;
    }

    Ok(RaftVoteResult {
        term: state.meta.current_term,
        vote_granted: granted,
    })
}

fn handle_vote_response(
    state: &mut WorkerState,
    from_prefix: u16,
    term: u64,
    vote_granted: bool,
) -> Result<(), crate::commit::CommitError> {
    // Stale response (from a peer that's already moved on) —
    // step down if the peer's term is higher.
    if term > state.meta.current_term {
        state.meta.current_term = term;
        state.meta.voted_for = None;
        state.role = Role::Follower;
        state.votes_received.clear();
        state.persist_meta()?;
        state.reset_election_timer();
        return Ok(());
    }

    // Only Candidates count votes, and only votes for the term
    // they're campaigning in.
    if state.role != Role::Candidate || term != state.meta.current_term {
        return Ok(());
    }

    if vote_granted {
        state.votes_received.insert(from_prefix);
        if state.votes_received.len() >= state.quorum() {
            debug!(
                me = state.cfg.me,
                term = state.meta.current_term,
                votes = state.votes_received.len(),
                quorum = state.quorum(),
                "raft: elected leader",
            );
            state.role = Role::Leader;
            state.votes_received.clear();
            // Phase 3.3 replaces this with a heartbeat tick.
            state.election_deadline = Instant::now() + Duration::from_secs(60);
        }
    }
    Ok(())
}

fn start_election(state: &mut WorkerState) -> Result<(), crate::commit::CommitError> {
    state.role = Role::Candidate;
    state.meta.current_term += 1;
    state.meta.voted_for = Some(state.cfg.me);
    state.persist_meta()?;
    state.votes_received.clear();
    state.votes_received.insert(state.cfg.me);

    let term = state.meta.current_term;
    let me = state.cfg.me;
    let rep_id = state.cfg.replication_id;
    let last_log_index = state.log.last_index();
    let last_log_term = state.log.last_term();

    debug!(
        me,
        term,
        members = state.cfg.members.len(),
        "raft: starting election",
    );

    if let Some(network) = state.network.clone() {
        for peer_prefix in state.cfg.members.iter().copied() {
            if peer_prefix == me {
                continue;
            }
            let Some(peer_id) = network.peer_for_prefix(peer_prefix) else {
                // Peer unreachable right now — election will time
                // out and retry.
                continue;
            };
            let rx = network.send_raft_vote(
                peer_id,
                rep_id,
                term,
                me,
                last_log_index,
                last_log_term,
            );
            let inbox_tx = state.inbox_tx.clone();
            thread::spawn(move || {
                if let Ok(resp) = rx.recv_timeout(VOTE_RPC_TIMEOUT) {
                    let _ = inbox_tx.send(RaftMsg::VoteResponse {
                        from_prefix: peer_prefix,
                        term: resp.term,
                        vote_granted: resp.vote_granted,
                    });
                }
            });
        }
    }

    // Single-node mode degenerates to "self-vote is the quorum".
    if state.votes_received.len() >= state.quorum() {
        state.role = Role::Leader;
        state.votes_received.clear();
        state.election_deadline = Instant::now() + Duration::from_secs(60);
    } else {
        state.reset_election_timer();
    }
    Ok(())
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
            // Long timeout so unit tests that exercise inbound
            // RPCs aren't racing the election timer.
            election_timeout_ms: (5_000, 10_000),
        }
    }

    #[test]
    fn request_vote_grants_when_log_is_empty() {
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA), None);
        let h = worker.handler();
        // Empty log on both sides + higher term + no prior vote
        // → grant. Up-to-date check passes trivially.
        let resp = h.request_vote(&[0xC0; 32], 0xBBBB, 5, 0, 0);
        assert!(resp.vote_granted);
        assert_eq!(resp.term, 5);
        worker.shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn append_entries_heartbeat_advances_term_and_persists() {
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA), None);
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
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA), None);
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
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA), None);
        // Drop sends shutdown + joins.
        drop(worker);
        // DB is still openable post-drop.
        let _ = RaftMeta::load(&db).unwrap();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn at_most_one_vote_per_term() {
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA), None);
        let h = worker.handler();
        // First voter wins term 5.
        let resp = h.request_vote(&[0xC0; 32], 0xBBBB, 5, 0, 0);
        assert!(resp.vote_granted);
        // Same candidate asking again at the same term — granted
        // (idempotent re-grant).
        let resp = h.request_vote(&[0xC0; 32], 0xBBBB, 5, 0, 0);
        assert!(resp.vote_granted);
        // Different candidate at the same term — refused.
        let resp = h.request_vote(&[0xC0; 32], 0xCCCC, 5, 0, 0);
        assert!(!resp.vote_granted);
        // Different candidate at a higher term — granted (the
        // higher term clears `voted_for`).
        let resp = h.request_vote(&[0xC0; 32], 0xCCCC, 6, 0, 0);
        assert!(resp.vote_granted);
        worker.shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn solo_candidate_with_quorum_of_one_becomes_leader() {
        // Single-member cluster: the candidate's self-vote is the
        // quorum, so the very first election fires + wins.
        let (db, dir) = temp_db();
        let cfg = WorkerConfig {
            me: 0xAAAA,
            members: vec![0xAAAA],
            replication_id: [0xC0; 32],
            // Tiny timeout so the test doesn't have to wait long.
            election_timeout_ms: (10, 30),
        };
        let worker = RaftWorker::spawn(db.clone(), cfg, None);
        let h = worker.handler();
        // Wait for the election to fire + complete.
        let snap = wait_for_role(&h, Role::Leader, Duration::from_millis(500));
        assert_eq!(snap.role, Role::Leader);
        assert!(snap.current_term >= 1);
        assert_eq!(snap.voted_for, Some(0xAAAA));
        worker.shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    fn wait_for_role(h: &WorkerHandle, want: Role, deadline: Duration) -> WorkerSnapshot {
        let until = std::time::Instant::now() + deadline;
        loop {
            if let Some(snap) = h.snapshot() {
                if snap.role == want {
                    return snap;
                }
            }
            if std::time::Instant::now() >= until {
                let snap = h.snapshot().expect("worker still alive");
                panic!(
                    "worker did not reach {want:?} within {deadline:?}; \
                     last snapshot: {snap:?}",
                );
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }
}
