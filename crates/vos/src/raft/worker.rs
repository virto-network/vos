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

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use std::sync::mpsc as std_mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use redb::Database;
use tracing::{debug, warn};

use crate::commit::CommitError;
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
    /// Leader heartbeat interval in milliseconds. The leader
    /// fires an empty `AppendEntries` to every follower on this
    /// tick to reset their election timers. Should be
    /// substantially smaller than `election_timeout_ms.0` so
    /// followers always see a heartbeat before timing out
    /// (Raft's standard guidance: ~10× smaller).
    pub heartbeat_interval_ms: u64,
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
    /// Drained by the worker after every outbound heartbeat
    /// `send_raft_append` helper thread receives the peer's
    /// reply. Used by the leader to detect a stale-term step-down
    /// (peer's term > ours) and, in phase 4, to advance
    /// match_index for replication.
    AppendResponse {
        from_prefix: u16,
        term: u64,
        success: bool,
        match_index: u64,
    },
    /// Test/diagnostic: snapshot the worker's role + term.
    QueryState {
        reply: std_mpsc::Sender<WorkerSnapshot>,
    },
    /// Append a new entry to the leader's log. Used by the agent
    /// thread (phase 5) and by tests injecting entries directly.
    /// On a Leader: appends, returns the new index. On any other
    /// role: returns `ProposeError::NotLeader`.
    Propose {
        payload: Vec<u8>,
        reply: std_mpsc::Sender<Result<u64, ProposeError>>,
    },
    Shutdown,
}

/// Reasons a propose can fail at the worker boundary.
#[derive(Debug)]
pub enum ProposeError {
    /// This worker is currently `Follower` or `Candidate` — phase 5
    /// will wire follower → leader forwarding; for now the caller
    /// must retry against the cluster's leader.
    NotLeader,
    /// redb write failed on the append.
    Storage(CommitError),
}

impl core::fmt::Display for ProposeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotLeader => write!(f, "propose: not leader"),
            Self::Storage(e) => write!(f, "propose: storage: {e}"),
        }
    }
}
impl std::error::Error for ProposeError {}

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

    /// Append a new payload to the cluster log. Caller is expected
    /// to address a Leader; followers / candidates return
    /// `NotLeader`. The returned index is the position the leader
    /// reserved for the entry — replication to a quorum is async,
    /// so the entry is *appended* by the time this returns but
    /// only *committed* once a majority of followers ack via
    /// `AppendResponse`. Phase 5 will turn this into a blocking
    /// "propose-and-wait-for-commit" call from the agent thread.
    pub fn propose(&self, payload: Vec<u8>) -> Result<u64, ProposeError> {
        let (tx, rx) = std_mpsc::channel();
        self.inbox
            .send(RaftMsg::Propose { payload, reply: tx })
            .map_err(|_| ProposeError::NotLeader)?;
        rx.recv_timeout(Duration::from_secs(2))
            .unwrap_or(Err(ProposeError::NotLeader))
    }
}

/// Worker state. Owns the per-group state machine + the
/// in-memory tally for an in-flight election + per-follower
/// replication bookkeeping when leader.
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
    /// Next election timeout. Followers refresh on every accepted
    /// heartbeat / granted vote; candidates refresh when starting
    /// an election; leaders use it as the heartbeat tick interval.
    election_deadline: Instant,
    /// Set of voters that have granted us a vote *in this term*.
    /// Includes ourselves the moment we become Candidate.
    votes_received: alloc::collections::BTreeSet<u16>,
    /// Per-follower replication state. `None` unless we're Leader.
    leader: Option<LeaderState>,
}

/// Per-follower replication bookkeeping. Initialized when a
/// worker becomes Leader; cleared when it steps down.
#[derive(Debug)]
struct LeaderState {
    /// Index of the next log entry to send to each follower.
    /// Initialized to `leader.last_log_index + 1` and adjusted
    /// based on each follower's `AppendResponse` (success bumps,
    /// failure decrements).
    next_index: BTreeMap<u16, u64>,
    /// Highest log index known to be replicated to each follower.
    /// Initialized to 0 and advanced on `AppendResponse {
    /// success: true }`.
    match_index: BTreeMap<u16, u64>,
}

impl LeaderState {
    fn fresh(members: &[u16], me: u16, last_log_index: u64) -> Self {
        let next_index = members
            .iter()
            .copied()
            .filter(|p| *p != me)
            .map(|p| (p, last_log_index + 1))
            .collect();
        let match_index = members
            .iter()
            .copied()
            .filter(|p| *p != me)
            .map(|p| (p, 0u64))
            .collect();
        Self {
            next_index,
            match_index,
        }
    }
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
            leader: None,
        };
        s.reset_election_timer();
        Ok(s)
    }

    /// Peers' match_index plus our own implicit "last_log_index" —
    /// used by the commit-advance routine to find the highest
    /// index a majority has replicated. Returns sorted descending
    /// so the position at index `quorum() - 1` is the highest
    /// index a majority of cluster members (counting ourselves)
    /// is at or above.
    fn match_index_majority_floor(&self) -> Option<u64> {
        let leader = self.leader.as_ref()?;
        let mut indices: Vec<u64> = leader.match_index.values().copied().collect();
        // Our own "match index" is our last_index — we have every
        // entry we've appended.
        indices.push(self.log.last_index());
        indices.sort_unstable_by(|a, b| b.cmp(a));
        let q = self.quorum();
        if q == 0 || q > indices.len() {
            return None;
        }
        Some(indices[q - 1])
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
                prev_log_term,
                leader_commit,
                entries,
                reply,
            }) => {
                let resp = handle_append_entries(
                    &mut state,
                    from_prefix,
                    term,
                    prev_log_index,
                    prev_log_term,
                    leader_commit,
                    entries,
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
            Ok(RaftMsg::AppendResponse {
                from_prefix,
                term,
                success,
                match_index,
            }) => {
                handle_append_response(
                    &mut state,
                    from_prefix,
                    term,
                    success,
                    match_index,
                )?;
            }
            Ok(RaftMsg::Propose { payload, reply }) => {
                let result = handle_propose(&mut state, payload);
                let _ = reply.send(result);
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => match state.role {
                Role::Follower | Role::Candidate => start_election(&mut state)?,
                Role::Leader => send_heartbeats(&mut state),
            },
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
    prev_log_term: u64,
    leader_commit: u64,
    entries: Vec<RaftEntry>,
) -> Result<RaftAppendResult, crate::commit::CommitError> {
    // Stale leader: term too low, refuse without changing anything.
    if term < state.meta.current_term {
        return Ok(RaftAppendResult {
            term: state.meta.current_term,
            success: false,
            match_index: 0,
        });
    }

    if term > state.meta.current_term {
        state.meta.current_term = term;
        state.meta.voted_for = None;
    }
    // Any AppendEntries from a current-term leader is a legitimate
    // signal to step down to Follower (whether we were Candidate
    // or a stale Leader at a lower term). Reset the election
    // timer regardless of the consistency check below — the
    // sender *is* the legitimate leader for this term.
    state.role = Role::Follower;
    state.votes_received.clear();
    state.reset_election_timer();

    // Consistency check: our log at prev_log_index must have
    // term prev_log_term. If we don't have an entry at
    // prev_log_index, or its term differs, refuse — the leader
    // will retry with an earlier prev_log_index until our logs
    // converge. (Phase 4 has no log compaction, so the retry
    // walks back at most last_index entries.)
    let our_prev_term = state.log.term_at(prev_log_index)?;
    let consistent = our_prev_term == Some(prev_log_term);
    if !consistent {
        // Persist the term/voted_for changes (if any) even on a
        // failed append — the higher-term observation must be
        // durable before we reply, otherwise a crash + restart
        // could grant a vote at a now-stale term.
        state.persist_meta()?;
        return Ok(RaftAppendResult {
            term: state.meta.current_term,
            success: false,
            match_index: 0,
        });
    }

    // Apply the entries inside one redb txn:
    //   1. Truncate any of our entries past prev_log_index that
    //      conflict with the leader's batch (different term at
    //      the same index).
    //   2. Append the new ones starting at prev_log_index + 1.
    //   3. Advance commit_index = min(leader_commit, last_index).
    //   4. Persist meta + log atomically.
    let txn = state.db.begin_write()?;

    // Find the first divergence between leader's batch and ours,
    // truncating from there. If everything matches up to our
    // tail, nothing to truncate; we'll just append the leftover.
    let mut conflict_at: Option<u64> = None;
    let mut already_present = 0usize;
    for (i, e) in entries.iter().enumerate() {
        let idx = prev_log_index + 1 + i as u64;
        match state.log.term_at(idx)? {
            Some(t) if t == e.term => {
                already_present += 1;
            }
            Some(_) => {
                conflict_at = Some(idx);
                break;
            }
            None => break,
        }
    }
    if let Some(idx) = conflict_at {
        state.log.truncate_after_in_txn(&txn, idx - 1)?;
    }
    for (i, e) in entries.iter().enumerate().skip(already_present) {
        let idx = prev_log_index + 1 + i as u64;
        // Append in order. truncate_after_in_txn (if it ran) has
        // dropped everything past prev_log_index + already_present;
        // append fills back from there.
        let _ = idx; // index is implicit in append_in_txn
        state.log.append_in_txn(&txn, e.term, &e.payload)?;
    }

    let last_new_index = prev_log_index + entries.len() as u64;
    if leader_commit > state.meta.commit_index {
        let new_commit = leader_commit.min(last_new_index);
        if new_commit > state.meta.commit_index {
            state.meta.commit_index = new_commit;
            // Phase 4 advances `last_applied` straight to
            // `commit_index`. The actor's dispatch isn't yet wired
            // through the worker (that's phase 5) — we're just
            // tracking the storage shape so phase 5 has a clean
            // boundary to plug into. The replay path in
            // `RaftCommit::replay_logs` consumes 1..=last_applied,
            // so the agent's cold-start replay still produces the
            // right state.
            state.meta.last_applied = state.meta.last_applied.max(new_commit);
        }
    }
    state.meta.write_in_txn(&txn)?;
    txn.commit()?;

    let _ = from_prefix; // logged at the dispatch site if needed

    Ok(RaftAppendResult {
        term: state.meta.current_term,
        success: true,
        match_index: last_new_index,
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
        // Step down if we were Candidate / Leader at the lower
        // term — clears `votes_received` and leader bookkeeping.
        step_down(state);
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
        state.persist_meta()?;
        step_down(state);
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
            become_leader(state);
        }
    }
    Ok(())
}

/// Transition into the Leader role: clear the in-flight election,
/// initialize per-follower replication state, and fire an
/// immediate replication tick so followers' election timers reset
/// before they can challenge us.
fn become_leader(state: &mut WorkerState) {
    state.role = Role::Leader;
    state.votes_received.clear();
    let last = state.log.last_index();
    state.leader = Some(LeaderState::fresh(&state.cfg.members, state.cfg.me, last));
    send_heartbeats(state);
}

/// Step down from Leader / Candidate to Follower. Clears the
/// transient role state (vote tally, per-follower bookkeeping)
/// and resets the election timer.
fn step_down(state: &mut WorkerState) {
    state.role = Role::Follower;
    state.votes_received.clear();
    state.leader = None;
    state.reset_election_timer();
}

/// Fire one round of `AppendEntries` to every follower. Each
/// follower receives entries from its `next_index` up to the
/// leader's tail (capped by `MAX_RAFT_ENTRIES` indirectly via
/// the wire format's per-frame limit). If a follower is
/// up-to-date, the call carries an empty entries vec — that's
/// the heartbeat case. Replies route back through the worker's
/// inbox as `RaftMsg::AppendResponse` so the per-follower
/// bookkeeping is updated on the single-threaded state machine.
fn send_heartbeats(state: &mut WorkerState) {
    let term = state.meta.current_term;
    let me = state.cfg.me;
    let rep_id = state.cfg.replication_id;
    let leader_last_index = state.log.last_index();
    let leader_commit = state.meta.commit_index;

    let Some(network) = state.network.clone() else {
        // No network → can't replicate. Just push the deadline so
        // we don't spin. Tests in single-node mode hit this.
        state.election_deadline =
            Instant::now() + Duration::from_millis(state.cfg.heartbeat_interval_ms);
        return;
    };

    let leader = match state.leader.as_ref() {
        Some(l) => l.clone_indices(),
        None => return,
    };

    for peer_prefix in state.cfg.members.iter().copied() {
        if peer_prefix == me {
            continue;
        }
        let next_idx = leader.next_index.get(&peer_prefix).copied().unwrap_or(1);
        // prev_log_index/term identifies the entry just before
        // what we're about to send, so the follower's consistency
        // check has something to anchor on.
        let prev_log_index = next_idx.saturating_sub(1);
        let prev_log_term = match state.log.term_at(prev_log_index) {
            Ok(Some(t)) => t,
            Ok(None) | Err(_) => 0,
        };
        // Read the entries to send. For a follower at the leader's
        // tail (next_idx == last_index + 1), this is empty — a
        // pure heartbeat.
        let entries = if next_idx <= leader_last_index {
            match state.log.entries(next_idx, leader_last_index) {
                Ok(es) => es
                    .into_iter()
                    .map(|e| RaftEntry {
                        term: e.term,
                        payload: e.payload,
                    })
                    .collect(),
                Err(_) => Vec::new(),
            }
        } else {
            Vec::new()
        };

        let Some(peer_id) = network.peer_for_prefix(peer_prefix) else {
            continue;
        };
        let rx = network.send_raft_append(
            peer_id,
            rep_id,
            term,
            me,
            prev_log_index,
            prev_log_term,
            leader_commit,
            entries,
        );
        let inbox_tx = state.inbox_tx.clone();
        thread::spawn(move || {
            if let Ok(resp) = rx.recv_timeout(VOTE_RPC_TIMEOUT) {
                let _ = inbox_tx.send(RaftMsg::AppendResponse {
                    from_prefix: peer_prefix,
                    term: resp.term,
                    success: resp.success,
                    match_index: resp.match_index,
                });
            }
        });
    }

    state.election_deadline =
        Instant::now() + Duration::from_millis(state.cfg.heartbeat_interval_ms);
}

impl LeaderState {
    /// Snapshot of the per-follower indices for the duration of
    /// one `send_heartbeats` round. Used so we can release the
    /// borrow on `state.leader` while we read the log + spawn
    /// helper threads.
    fn clone_indices(&self) -> Self {
        Self {
            next_index: self.next_index.clone(),
            match_index: self.match_index.clone(),
        }
    }
}

fn handle_append_response(
    state: &mut WorkerState,
    from_prefix: u16,
    term: u64,
    success: bool,
    match_index: u64,
) -> Result<(), CommitError> {
    // Stale-term detection: peer's term > ours → step down. Same
    // shape phase 3 used.
    if term > state.meta.current_term {
        debug!(
            me = state.cfg.me,
            peer = from_prefix,
            peer_term = term,
            our_term = state.meta.current_term,
            "raft: leader stepping down — peer at higher term",
        );
        state.meta.current_term = term;
        state.meta.voted_for = None;
        state.persist_meta()?;
        step_down(state);
        return Ok(());
    }

    // Only Leaders track per-follower replication.
    if state.role != Role::Leader || term != state.meta.current_term {
        return Ok(());
    }

    let leader = match state.leader.as_mut() {
        Some(l) => l,
        None => return Ok(()),
    };
    if success {
        leader.match_index.insert(from_prefix, match_index);
        leader.next_index.insert(from_prefix, match_index + 1);
        try_advance_commit_index(state)?;
    } else {
        // Consistency-check failure: the follower has a divergent
        // log at our `prev_log_index`. Walk our `next_index` for
        // them backward by one and retry on the next heartbeat
        // tick. (Phase 4 doesn't optimize the back-step rate;
        // log compaction in phase 6 will replace the worst-case
        // walk-to-zero with a snapshot install.)
        let cur = leader.next_index.get(&from_prefix).copied().unwrap_or(1);
        let new_next = cur.saturating_sub(1).max(1);
        leader.next_index.insert(from_prefix, new_next);
    }
    Ok(())
}

/// Commit-advance: the highest index that's replicated on a
/// majority of cluster members AND was appended in the current
/// term moves the commit_index forward.
fn try_advance_commit_index(state: &mut WorkerState) -> Result<(), CommitError> {
    let Some(majority_floor) = state.match_index_majority_floor() else {
        return Ok(());
    };
    if majority_floor <= state.meta.commit_index {
        return Ok(());
    }
    // Raft safety: the leader can only commit entries from its
    // current term via majority match. Earlier-term entries
    // become committed implicitly when a later same-term entry
    // commits.
    let entry_term = state.log.term_at(majority_floor)?;
    if entry_term != Some(state.meta.current_term) {
        return Ok(());
    }
    debug!(
        me = state.cfg.me,
        from = state.meta.commit_index,
        to = majority_floor,
        "raft: leader advancing commit_index",
    );
    state.meta.commit_index = majority_floor;
    // Phase 4.2 mirrors phase 4.1's follower-side stub: push
    // last_applied straight to commit_index. Phase 5 plumbs the
    // actor's dispatch through a reply channel and decouples
    // these two indices.
    state.meta.last_applied = state.meta.last_applied.max(majority_floor);
    state.persist_meta()?;
    Ok(())
}

fn handle_propose(state: &mut WorkerState, payload: Vec<u8>) -> Result<u64, ProposeError> {
    if state.role != Role::Leader {
        return Err(ProposeError::NotLeader);
    }
    let term = state.meta.current_term;
    let txn = state.db.begin_write().map_err(|e| ProposeError::Storage(e.into()))?;
    let index = state
        .log
        .append_in_txn(&txn, term, &payload)
        .map_err(ProposeError::Storage)?;
    txn.commit().map_err(|e| ProposeError::Storage(e.into()))?;
    Ok(index)
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
        become_leader(state);
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
            heartbeat_interval_ms: 500,
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
    fn follower_appends_entries_and_advances_commit_index() {
        // Phase 4.1: AppendEntries with non-empty `entries` and a
        // matching prev_log_index/term is accepted, the entries
        // land in `raft_log`, and `commit_index` advances to
        // min(leader_commit, last_new_index).
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA), None);
        let h = worker.handler();

        // Leader sends two entries from the empty pre-log slot.
        let resp = h.append_entries(
            &[0xC0; 32], 0xBBBB,
            5,                  // term
            0,                  // prev_log_index
            0,                  // prev_log_term
            2,                  // leader_commit (covers both entries)
            vec![
                RaftEntry { term: 5, payload: b"a".to_vec() },
                RaftEntry { term: 5, payload: b"b".to_vec() },
            ],
        );
        assert!(resp.success);
        assert_eq!(resp.match_index, 2);
        assert_eq!(resp.term, 5);

        let log = RaftLog::open(db.clone()).unwrap();
        assert_eq!(log.last_index(), 2);
        assert_eq!(log.last_term(), 5);
        let entries = log.entries(1, 2).unwrap();
        assert_eq!(entries[0].payload, b"a");
        assert_eq!(entries[1].payload, b"b");

        let meta = RaftMeta::load(&db).unwrap();
        assert_eq!(meta.commit_index, 2);
        assert_eq!(meta.last_applied, 2);

        worker.shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn follower_rejects_inconsistent_prev_log() {
        // Append two entries successfully, then a leader at a
        // higher term arrives claiming `prev_log_index=2`,
        // `prev_log_term=99` — our entry at index 2 has term 5,
        // not 99, so the consistency check refuses.
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA), None);
        let h = worker.handler();
        h.append_entries(
            &[0xC0; 32], 0xBBBB, 5, 0, 0, 0,
            vec![
                RaftEntry { term: 5, payload: b"a".to_vec() },
                RaftEntry { term: 5, payload: b"b".to_vec() },
            ],
        );
        let resp = h.append_entries(
            &[0xC0; 32], 0xBBBB,
            7,    // term (we adopt this)
            2,    // prev_log_index
            99,   // prev_log_term — doesn't match our 5
            2,
            vec![RaftEntry { term: 7, payload: b"c".to_vec() }],
        );
        assert!(!resp.success, "consistency check refuses divergent prev_log_term");
        assert_eq!(resp.term, 7, "term still adopted on a refusal");
        // The new term *is* persisted even on refusal.
        let meta = RaftMeta::load(&db).unwrap();
        assert_eq!(meta.current_term, 7);
        // The log was not extended.
        let log = RaftLog::open(db.clone()).unwrap();
        assert_eq!(log.last_index(), 2);
        worker.shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn follower_truncates_conflicting_tail_then_appends() {
        // Two entries land at term 5. A new leader at term 6
        // claims a different entry at index 2. We truncate our
        // index 2 and append the leader's authoritative version.
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA), None);
        let h = worker.handler();
        h.append_entries(
            &[0xC0; 32], 0xBBBB, 5, 0, 0, 0,
            vec![
                RaftEntry { term: 5, payload: b"a".to_vec() },
                RaftEntry { term: 5, payload: b"old-b".to_vec() },
            ],
        );
        let resp = h.append_entries(
            &[0xC0; 32], 0xCCCC,
            6,
            1,    // prev_log_index — matches our entry at term 5
            5,    // prev_log_term — also matches
            2,
            // entries[0] at index 2: leader has term 6, we have
            // term 5 → conflict, truncate, replace.
            vec![RaftEntry { term: 6, payload: b"new-b".to_vec() }],
        );
        assert!(resp.success);
        assert_eq!(resp.match_index, 2);

        let log = RaftLog::open(db.clone()).unwrap();
        let entries = log.entries(1, 2).unwrap();
        assert_eq!(entries[0].payload, b"a", "entry 1 untouched");
        assert_eq!(entries[1].payload, b"new-b", "entry 2 replaced");
        assert_eq!(entries[1].term, 6);

        worker.shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn follower_idempotent_on_already_present_entries() {
        // Same-term retry of an already-replicated batch must be
        // idempotent — no duplicate appends, match_index reflects
        // the existing tail.
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA), None);
        let h = worker.handler();
        for _ in 0..3 {
            let resp = h.append_entries(
                &[0xC0; 32], 0xBBBB, 5, 0, 0, 2,
                vec![
                    RaftEntry { term: 5, payload: b"a".to_vec() },
                    RaftEntry { term: 5, payload: b"b".to_vec() },
                ],
            );
            assert!(resp.success);
            assert_eq!(resp.match_index, 2);
        }
        let log = RaftLog::open(db.clone()).unwrap();
        assert_eq!(log.len().unwrap(), 2,
            "duplicate AppendEntries retries must not bloat the log");
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
            heartbeat_interval_ms: 500,
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

    #[test]
    fn propose_on_follower_is_rejected() {
        let (db, dir) = temp_db();
        let worker = RaftWorker::spawn(db.clone(), cfg(0xAAAA), None);
        let h = worker.handler();
        // Brand-new worker is Follower — propose must refuse.
        let err = h.propose(b"x".to_vec()).unwrap_err();
        assert!(matches!(err, ProposeError::NotLeader));
        worker.shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn solo_leader_propose_appends_entry_to_log() {
        // Single-member cluster: the worker becomes Leader on
        // its first election. A propose then lands an entry at
        // index 1, term 1 (the term of the win).
        let (db, dir) = temp_db();
        let cfg = WorkerConfig {
            me: 0xAAAA,
            members: vec![0xAAAA],
            replication_id: [0xC0; 32],
            election_timeout_ms: (10, 30),
            heartbeat_interval_ms: 500,
        };
        let worker = RaftWorker::spawn(db.clone(), cfg, None);
        let h = worker.handler();
        let _ = wait_for_role(&h, Role::Leader, Duration::from_millis(500));

        let idx = h.propose(b"first".to_vec()).expect("propose");
        assert_eq!(idx, 1);
        let idx2 = h.propose(b"second".to_vec()).expect("propose 2");
        assert_eq!(idx2, 2);

        let log = RaftLog::open(db.clone()).unwrap();
        assert_eq!(log.last_index(), 2);
        let entries = log.entries(1, 2).unwrap();
        assert_eq!(entries[0].payload, b"first");
        assert_eq!(entries[1].payload, b"second");
        // Both entries carry the term of the win — the test's
        // first-and-only term.
        assert_eq!(entries[0].term, entries[1].term);

        worker.shutdown();
        let _ = std::fs::remove_dir_all(dir);
    }
}
