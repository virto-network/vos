//! Per-replication-group Raft worker — the consensus state
//! machine.
//!
//! Owns: role, term, vote, per-follower replication indices,
//! election timer. Single-writer for the [`Storage`] backend.
//! Talks to peers through [`Transport`].
//!
//! Today: sync API, std mpsc inbox, real OS threads for outbound
//! RPCs. Commit 4 swaps to async (`futures::select!` over the
//! inbox + `Clock::sleep_until`) and replaces the helper threads
//! with executor-spawned tasks.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::sync::atomic::{AtomicU8, Ordering};
use std::sync::mpsc as std_mpsc;
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use crate::config::{Config, NodeId};
use crate::log_entry::LogEntry;
use crate::meta::Meta;
use crate::role::Role;
use crate::rpc::{
    AppendEntriesReq, AppendEntriesResp, InstallSnapshotReq, InstallSnapshotResp,
    RequestVoteReq, RequestVoteResp,
};
use crate::storage::{Storage, WriteBatch};
use crate::transport::Transport;

/// Hard upper bound on how long a single outbound vote helper
/// thread waits for a peer's reply before giving up. The election
/// timeout will fire long before this — the cap exists only so a
/// peer that drops a request without ever replying doesn't leak a
/// helper thread for the lifetime of the worker.
pub const VOTE_RPC_TIMEOUT: Duration = Duration::from_secs(2);

/// Hysteresis for the leader's auto-compaction. The worker only
/// compacts when the eligible-up-to-index is at least this many
/// entries past the current snap pointer; otherwise we'd open a
/// write txn on every heartbeat tick to drop a single entry.
pub const COMPACT_HYSTERESIS: u64 = 16;

/// Reasons a [`WorkerHandle::propose`] can fail.
#[derive(Debug)]
pub enum ProposeError<E> {
    /// This worker is currently `Follower` or `Candidate`. The
    /// caller must retry against the cluster's leader.
    NotLeader,
    /// Storage write failed on the append.
    Storage(E),
}

/// Diagnostic snapshot of a worker's state. Returned by
/// [`WorkerHandle::snapshot`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerSnapshot<N: NodeId> {
    pub role: Role,
    pub current_term: u64,
    pub voted_for: Option<N>,
    pub last_log_index: u64,
    pub commit_index: u64,
    pub last_applied: u64,
}

/// Inbound message processed by the worker loop. Variants pair
/// the inbound RPC types with reply channels so the request /
/// response pattern stays explicit.
#[allow(dead_code)]
pub enum RaftMsg<N: NodeId> {
    AppendEntries {
        from: N,
        req: AppendEntriesReq<N>,
        reply: std_mpsc::Sender<AppendEntriesResp>,
    },
    RequestVote {
        from: N,
        req: RequestVoteReq<N>,
        reply: std_mpsc::Sender<RequestVoteResp>,
    },
    InstallSnapshot {
        from: N,
        req: InstallSnapshotReq<N>,
        reply: std_mpsc::Sender<InstallSnapshotResp>,
    },
    /// Drained after every outbound `send_vote` / `send_append`
    /// / `send_install` helper thread receives the peer's reply.
    /// The variant carries the peer + the response so the worker
    /// can update per-peer bookkeeping on its single-threaded
    /// loop.
    VoteResponse {
        from: N,
        resp: RequestVoteResp,
    },
    AppendResponse {
        from: N,
        resp: AppendEntriesResp,
    },
    InstallSnapshotResponse {
        from: N,
        resp: InstallSnapshotResp,
        last_included_index: u64,
    },
    /// Append a new entry to the leader's log. Used by the agent
    /// thread (the host's commit_with_log path).
    Propose {
        payload: Vec<u8>,
        reply: std_mpsc::Sender<Result<u64, ProposeError<()>>>,
    },
    QueryState {
        reply: std_mpsc::Sender<WorkerSnapshot<N>>,
    },
    Shutdown,
}

/// Owning handle to a running worker. Drop or [`shutdown`] cleans
/// up the thread.
///
/// [`shutdown`]: Self::shutdown
pub struct Worker<N: NodeId> {
    inbox: std_mpsc::Sender<RaftMsg<N>>,
    role: Arc<AtomicU8>,
    join: Option<JoinHandle<()>>,
}

impl<N: NodeId> Worker<N> {
    /// Spawn a worker thread for one replication group.
    ///
    /// `apply_notifier` receives the new `commit_index` value
    /// each time the worker advances it (leader's quorum match
    /// or follower's heartbeat that bumps `leader_commit`).
    pub fn spawn<S, T>(
        storage: S,
        transport: Arc<T>,
        cfg: Config<N>,
        apply_notifier: Option<std_mpsc::Sender<u64>>,
    ) -> Self
    where
        S: Storage<N>,
        T: Transport<N>,
    {
        let (tx, rx) = std_mpsc::channel();
        let inbox_tx = tx.clone();
        let role = Arc::new(AtomicU8::new(Role::Follower.as_u8()));
        let role_for_thread = role.clone();
        let join = thread::Builder::new()
            .name(alloc::format!("raft-worker-{:?}", cfg.me))
            .spawn(move || {
                let _ = worker_loop::<N, S, T>(
                    storage,
                    transport,
                    cfg,
                    rx,
                    inbox_tx,
                    apply_notifier,
                    role_for_thread,
                );
            })
            .expect("spawn raft worker");
        Self {
            inbox: tx,
            role,
            join: Some(join),
        }
    }

    /// Cheap clone-able handle.
    pub fn handler(&self) -> WorkerHandle<N> {
        WorkerHandle {
            inbox: self.inbox.clone(),
            role: self.role.clone(),
        }
    }

    /// Lock-free read of the worker's current role.
    pub fn role(&self) -> Role {
        Role::from_u8(self.role.load(Ordering::Relaxed))
    }

    /// Stop the worker and join the thread.
    pub fn shutdown(mut self) {
        let _ = self.inbox.send(RaftMsg::Shutdown);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

impl<N: NodeId> Drop for Worker<N> {
    fn drop(&mut self) {
        let _ = self.inbox.send(RaftMsg::Shutdown);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Cheap-to-clone handle for sending messages into the worker.
#[derive(Clone)]
pub struct WorkerHandle<N: NodeId> {
    inbox: std_mpsc::Sender<RaftMsg<N>>,
    role: Arc<AtomicU8>,
}

impl<N: NodeId> WorkerHandle<N> {
    /// Lock-free read of the worker's current role.
    pub fn role(&self) -> Role {
        Role::from_u8(self.role.load(Ordering::Relaxed))
    }

    /// Cheap-to-clone sender for spawning helper tasks.
    pub fn sender(&self) -> std_mpsc::Sender<RaftMsg<N>> {
        self.inbox.clone()
    }

    /// Test / diagnostic — block briefly waiting for the worker
    /// to send back a snapshot. `None` if the worker is shut
    /// down or busy beyond the deadline.
    pub fn snapshot(&self) -> Option<WorkerSnapshot<N>> {
        let (tx, rx) = std_mpsc::channel();
        self.inbox.send(RaftMsg::QueryState { reply: tx }).ok()?;
        rx.recv_timeout(Duration::from_millis(500)).ok()
    }

    /// Append a new payload to the cluster log. Caller is
    /// expected to address a Leader; followers / candidates
    /// return `NotLeader`. The returned index is where the
    /// leader reserved a slot — replication to a quorum is
    /// async.
    pub fn propose(&self, payload: Vec<u8>) -> Result<u64, ProposeError<()>> {
        let (tx, rx) = std_mpsc::channel();
        self.inbox
            .send(RaftMsg::Propose { payload, reply: tx })
            .map_err(|_| ProposeError::NotLeader)?;
        rx.recv_timeout(Duration::from_secs(2))
            .unwrap_or(Err(ProposeError::NotLeader))
    }

    /// Inbound `AppendEntries` from a peer — sends to the worker
    /// inbox and blocks on the reply.
    pub fn handle_inbound_append(
        &self,
        from: N,
        req: AppendEntriesReq<N>,
    ) -> AppendEntriesResp {
        let (tx, rx) = std_mpsc::channel();
        if self
            .inbox
            .send(RaftMsg::AppendEntries { from, req: req.clone(), reply: tx })
            .is_err()
        {
            return AppendEntriesResp {
                term: req.term,
                success: false,
                match_index: 0,
            };
        }
        rx.recv().unwrap_or(AppendEntriesResp {
            term: req.term,
            success: false,
            match_index: 0,
        })
    }

    /// Inbound `RequestVote` from a peer.
    pub fn handle_inbound_vote(
        &self,
        from: N,
        req: RequestVoteReq<N>,
    ) -> RequestVoteResp {
        let (tx, rx) = std_mpsc::channel();
        if self
            .inbox
            .send(RaftMsg::RequestVote { from, req, reply: tx })
            .is_err()
        {
            return RequestVoteResp {
                term: req.term,
                vote_granted: false,
            };
        }
        rx.recv().unwrap_or(RequestVoteResp {
            term: req.term,
            vote_granted: false,
        })
    }

    /// Inbound `InstallSnapshot` from a peer.
    pub fn handle_inbound_install(
        &self,
        from: N,
        req: InstallSnapshotReq<N>,
    ) -> InstallSnapshotResp {
        let (tx, rx) = std_mpsc::channel();
        let term = req.term;
        if self
            .inbox
            .send(RaftMsg::InstallSnapshot { from, req, reply: tx })
            .is_err()
        {
            return InstallSnapshotResp { term };
        }
        rx.recv().unwrap_or(InstallSnapshotResp { term })
    }
}

/// Per-follower replication bookkeeping. Initialized when a
/// worker becomes Leader; cleared when it steps down.
#[derive(Debug, Clone)]
struct LeaderState<N: NodeId> {
    next_index: BTreeMap<N, u64>,
    match_index: BTreeMap<N, u64>,
}

impl<N: NodeId> LeaderState<N> {
    fn fresh(members: &[N], me: N, last_log_index: u64) -> Self {
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

/// Worker state. Owns the per-group state machine + the
/// in-memory tally for an in-flight election + per-follower
/// replication bookkeeping when leader.
struct WorkerState<N: NodeId, S: Storage<N>, T: Transport<N>> {
    storage: S,
    transport: Arc<T>,
    cfg: Config<N>,
    inbox_tx: std_mpsc::Sender<RaftMsg<N>>,
    role: Role,
    meta: Meta<N>,
    election_deadline: Instant,
    votes_received: BTreeSet<N>,
    leader: Option<LeaderState<N>>,
    apply_notifier: Option<std_mpsc::Sender<u64>>,
    role_atomic: Arc<AtomicU8>,
}

impl<N: NodeId, S: Storage<N>, T: Transport<N>> WorkerState<N, S, T> {
    fn open(
        storage: S,
        transport: Arc<T>,
        cfg: Config<N>,
        inbox_tx: std_mpsc::Sender<RaftMsg<N>>,
        apply_notifier: Option<std_mpsc::Sender<u64>>,
        role_atomic: Arc<AtomicU8>,
    ) -> Result<Self, S::Error> {
        let meta = storage.load_meta()?;
        let mut s = Self {
            storage,
            transport,
            cfg,
            inbox_tx,
            role: Role::Follower,
            meta,
            election_deadline: Instant::now(),
            votes_received: BTreeSet::new(),
            leader: None,
            apply_notifier,
            role_atomic,
        };
        s.reset_election_timer();
        s.publish_role();
        Ok(s)
    }

    fn publish_role(&self) {
        self.role_atomic
            .store(self.role.as_u8(), Ordering::Relaxed);
    }

    fn set_role(&mut self, role: Role) {
        self.role = role;
        self.publish_role();
    }

    fn fire_apply_notification(&self) {
        if let Some(tx) = self.apply_notifier.as_ref() {
            let _ = tx.send(self.meta.commit_index);
        }
    }

    fn reset_election_timer(&mut self) {
        let (lo, hi) = self.cfg.election_timeout_ms;
        let span = (hi.saturating_sub(lo)).max(1);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as u64)
            .unwrap_or(0);
        // Combine the wall-clock nanos with a hash of `me` so peers
        // don't all time out simultaneously.
        let me_seed = {
            use core::hash::{Hash, Hasher};
            let mut h = std::collections::hash_map::DefaultHasher::new();
            <N as Hash>::hash(&self.cfg.me, &mut h);
            h.finish()
        };
        let jitter = (nanos.wrapping_mul(0x9E3779B97F4A7C15) ^ me_seed ^ self.meta.current_term)
            % span;
        let timeout = Duration::from_millis(lo + jitter);
        self.election_deadline = Instant::now() + timeout;
    }

    /// Quorum size — majority of total members (counting self).
    fn quorum(&self) -> usize {
        self.cfg.quorum()
    }

    /// Snapshot of `match_index` values (followers + leader's
    /// own last_index) sorted descending. Position
    /// `quorum() - 1` is the highest index a majority is at or
    /// above.
    fn match_index_majority_floor(&self) -> Option<u64> {
        let leader = self.leader.as_ref()?;
        let mut indices: Vec<u64> = leader.match_index.values().copied().collect();
        indices.push(self.storage.last_index());
        indices.sort_unstable_by(|a, b| b.cmp(a));
        let q = self.quorum();
        if q == 0 || q > indices.len() {
            return None;
        }
        Some(indices[q - 1])
    }
}

fn worker_loop<N, S, T>(
    storage: S,
    transport: Arc<T>,
    cfg: Config<N>,
    inbox: std_mpsc::Receiver<RaftMsg<N>>,
    inbox_tx: std_mpsc::Sender<RaftMsg<N>>,
    apply_notifier: Option<std_mpsc::Sender<u64>>,
    role_atomic: Arc<AtomicU8>,
) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
{
    let mut state = WorkerState::<N, S, T>::open(
        storage,
        transport,
        cfg,
        inbox_tx,
        apply_notifier,
        role_atomic,
    )?;

    loop {
        let now = Instant::now();
        let timeout = state.election_deadline.saturating_duration_since(now);
        match inbox.recv_timeout(timeout) {
            Ok(RaftMsg::Shutdown) => break,
            Ok(RaftMsg::AppendEntries { from, req, reply }) => {
                let resp = handle_append_entries(&mut state, from, req)?;
                let _ = reply.send(resp);
            }
            Ok(RaftMsg::RequestVote { from, req, reply }) => {
                let resp = handle_request_vote(&mut state, from, req)?;
                let _ = reply.send(resp);
            }
            Ok(RaftMsg::InstallSnapshot { from, req, reply }) => {
                let resp = handle_install_snapshot(&mut state, from, req)?;
                let _ = reply.send(resp);
            }
            Ok(RaftMsg::AppendResponse { from, resp }) => {
                handle_append_response(&mut state, from, resp)?;
            }
            Ok(RaftMsg::VoteResponse { from, resp }) => {
                handle_vote_response(&mut state, from, resp)?;
            }
            Ok(RaftMsg::InstallSnapshotResponse { from, resp, last_included_index }) => {
                handle_install_snapshot_response(&mut state, from, resp, last_included_index)?;
            }
            Ok(RaftMsg::Propose { payload, reply }) => {
                let result = handle_propose(&mut state, payload);
                let _ = reply.send(result);
            }
            Ok(RaftMsg::QueryState { reply }) => {
                let _ = reply.send(WorkerSnapshot {
                    role: state.role,
                    current_term: state.meta.current_term,
                    voted_for: state.meta.voted_for,
                    last_log_index: state.storage.last_index(),
                    commit_index: state.meta.commit_index,
                    last_applied: state.meta.last_applied,
                });
            }
            Err(std_mpsc::RecvTimeoutError::Timeout) => match state.role {
                Role::Follower | Role::Candidate => start_election(&mut state)?,
                Role::Leader => send_heartbeats(&mut state)?,
            },
            Err(std_mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }
    Ok(())
}

fn handle_append_entries<N, S, T>(
    state: &mut WorkerState<N, S, T>,
    _from: N,
    req: AppendEntriesReq<N>,
) -> Result<AppendEntriesResp, S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
{
    if req.term < state.meta.current_term {
        return Ok(AppendEntriesResp {
            term: state.meta.current_term,
            success: false,
            match_index: 0,
        });
    }

    if req.term > state.meta.current_term {
        state.meta.current_term = req.term;
        state.meta.voted_for = None;
    }
    state.set_role(Role::Follower);
    state.votes_received.clear();
    state.leader = None;
    state.reset_election_timer();

    let our_prev_term = state.storage.term_at(req.prev_log_index)?;
    let consistent = our_prev_term == Some(req.prev_log_term);
    if !consistent {
        // Persist the term/voted_for changes (if any) on a
        // failed append — durability matters even on refusal.
        state.storage.commit_batch(WriteBatch {
            meta: Some(state.meta.clone()),
            ..Default::default()
        })?;
        return Ok(AppendEntriesResp {
            term: state.meta.current_term,
            success: false,
            match_index: 0,
        });
    }

    // Find the first divergence between leader's batch and ours,
    // truncating from there. If everything matches up to our
    // tail, nothing to truncate; we'll just append the leftover.
    let mut conflict_at: Option<u64> = None;
    let mut already_present = 0usize;
    for (i, e) in req.entries.iter().enumerate() {
        let idx = req.prev_log_index + 1 + i as u64;
        match state.storage.term_at(idx)? {
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
    let truncate_after = conflict_at.map(|idx| idx - 1);
    let appends: Vec<LogEntry> = req
        .entries
        .iter()
        .enumerate()
        .skip(already_present)
        .map(|(i, e)| LogEntry {
            index: req.prev_log_index + 1 + i as u64,
            term: e.term,
            payload: e.payload.clone(),
        })
        .collect();

    let last_new_index = req.prev_log_index + req.entries.len() as u64;
    let mut commit_advanced = false;
    if req.leader_commit > state.meta.commit_index {
        let new_commit = req.leader_commit.min(last_new_index);
        if new_commit > state.meta.commit_index {
            state.meta.commit_index = new_commit;
            state.meta.last_applied = state.meta.last_applied.max(new_commit);
            commit_advanced = true;
        }
    }

    state.storage.commit_batch(WriteBatch {
        truncate_after,
        compact_to: None,
        appends,
        state: None,
        meta: Some(state.meta.clone()),
    })?;

    if commit_advanced {
        state.fire_apply_notification();
    }

    Ok(AppendEntriesResp {
        term: state.meta.current_term,
        success: true,
        match_index: last_new_index,
    })
}

fn handle_request_vote<N, S, T>(
    state: &mut WorkerState<N, S, T>,
    _from: N,
    req: RequestVoteReq<N>,
) -> Result<RequestVoteResp, S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
{
    if req.term < state.meta.current_term {
        return Ok(RequestVoteResp {
            term: state.meta.current_term,
            vote_granted: false,
        });
    }

    let mut meta_changed = false;
    if req.term > state.meta.current_term {
        state.meta.current_term = req.term;
        state.meta.voted_for = None;
        step_down(state);
        meta_changed = true;
    }

    let our_last_term = state.storage.last_term();
    let our_last_index = state.storage.last_index();
    let candidate_up_to_date = (req.last_log_term > our_last_term)
        || (req.last_log_term == our_last_term && req.last_log_index >= our_last_index);

    let already_voted_otherwise = state
        .meta
        .voted_for
        .is_some_and(|v| v != req.candidate);

    let granted = !already_voted_otherwise && candidate_up_to_date;

    if granted {
        state.meta.voted_for = Some(req.candidate);
        state.reset_election_timer();
        meta_changed = true;
    }

    if meta_changed {
        state.storage.commit_batch(WriteBatch {
            meta: Some(state.meta.clone()),
            ..Default::default()
        })?;
    }

    Ok(RequestVoteResp {
        term: state.meta.current_term,
        vote_granted: granted,
    })
}

fn handle_install_snapshot<N, S, T>(
    state: &mut WorkerState<N, S, T>,
    _from: N,
    req: InstallSnapshotReq<N>,
) -> Result<InstallSnapshotResp, S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
{
    if req.term < state.meta.current_term {
        return Ok(InstallSnapshotResp {
            term: state.meta.current_term,
        });
    }
    if req.term > state.meta.current_term {
        state.meta.current_term = req.term;
        state.meta.voted_for = None;
    }
    state.set_role(Role::Follower);
    state.votes_received.clear();
    state.leader = None;
    state.reset_election_timer();

    if req.last_included_index <= state.storage.snap_last_index() {
        // Idempotent retry — refresh meta + reply.
        state.storage.commit_batch(WriteBatch {
            meta: Some(state.meta.clone()),
            ..Default::default()
        })?;
        return Ok(InstallSnapshotResp {
            term: state.meta.current_term,
        });
    }

    state.meta.snap_last_index = req.last_included_index;
    state.meta.snap_last_term = req.last_included_term;
    state.meta.commit_index = state.meta.commit_index.max(req.last_included_index);
    state.meta.last_applied = state.meta.last_applied.max(req.last_included_index);

    state.storage.commit_batch(WriteBatch {
        compact_to: Some((req.last_included_index, req.last_included_term)),
        state: Some(req.snapshot),
        meta: Some(state.meta.clone()),
        ..Default::default()
    })?;

    state.fire_apply_notification();
    Ok(InstallSnapshotResp {
        term: state.meta.current_term,
    })
}

fn handle_append_response<N, S, T>(
    state: &mut WorkerState<N, S, T>,
    from: N,
    resp: AppendEntriesResp,
) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
{
    if resp.term > state.meta.current_term {
        state.meta.current_term = resp.term;
        state.meta.voted_for = None;
        state.storage.commit_batch(WriteBatch {
            meta: Some(state.meta.clone()),
            ..Default::default()
        })?;
        step_down(state);
        return Ok(());
    }
    if state.role != Role::Leader || resp.term != state.meta.current_term {
        return Ok(());
    }
    let leader = match state.leader.as_mut() {
        Some(l) => l,
        None => return Ok(()),
    };
    if resp.success {
        leader.match_index.insert(from, resp.match_index);
        leader.next_index.insert(from, resp.match_index + 1);
        try_advance_commit_index(state)?;
    } else {
        let cur = leader.next_index.get(&from).copied().unwrap_or(1);
        let new_next = cur.saturating_sub(1).max(1);
        leader.next_index.insert(from, new_next);
    }
    Ok(())
}

fn handle_install_snapshot_response<N, S, T>(
    state: &mut WorkerState<N, S, T>,
    from: N,
    resp: InstallSnapshotResp,
    last_included_index: u64,
) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
{
    if resp.term > state.meta.current_term {
        state.meta.current_term = resp.term;
        state.meta.voted_for = None;
        state.storage.commit_batch(WriteBatch {
            meta: Some(state.meta.clone()),
            ..Default::default()
        })?;
        step_down(state);
        return Ok(());
    }
    if state.role != Role::Leader || resp.term != state.meta.current_term {
        return Ok(());
    }
    if let Some(leader) = state.leader.as_mut() {
        let prev_match = leader.match_index.get(&from).copied().unwrap_or(0);
        if last_included_index > prev_match {
            leader.match_index.insert(from, last_included_index);
        }
        leader.next_index.insert(from, last_included_index + 1);
    }
    Ok(())
}

fn handle_vote_response<N, S, T>(
    state: &mut WorkerState<N, S, T>,
    from: N,
    resp: RequestVoteResp,
) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
{
    if resp.term > state.meta.current_term {
        state.meta.current_term = resp.term;
        state.meta.voted_for = None;
        state.storage.commit_batch(WriteBatch {
            meta: Some(state.meta.clone()),
            ..Default::default()
        })?;
        step_down(state);
        return Ok(());
    }
    if state.role != Role::Candidate || resp.term != state.meta.current_term {
        return Ok(());
    }
    if resp.vote_granted {
        state.votes_received.insert(from);
        if state.votes_received.len() >= state.quorum() {
            become_leader(state)?;
        }
    }
    Ok(())
}

fn handle_propose<N, S, T>(
    state: &mut WorkerState<N, S, T>,
    payload: Vec<u8>,
) -> Result<u64, ProposeError<()>>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
{
    if state.role != Role::Leader {
        return Err(ProposeError::NotLeader);
    }
    let term = state.meta.current_term;
    let new_index = state.storage.last_index() + 1;
    let entry = LogEntry {
        index: new_index,
        term,
        payload,
    };
    state
        .storage
        .commit_batch(WriteBatch {
            appends: alloc::vec![entry],
            ..Default::default()
        })
        .map_err(|_| ProposeError::Storage(()))?;
    // Single-node cluster: own last_index IS the quorum, advance
    // commit synchronously.
    let _ = try_advance_commit_index(state);
    Ok(new_index)
}

fn become_leader<N, S, T>(state: &mut WorkerState<N, S, T>) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
{
    state.set_role(Role::Leader);
    state.votes_received.clear();
    let last = state.storage.last_index();
    state.leader = Some(LeaderState::fresh(&state.cfg.members, state.cfg.me, last));
    send_heartbeats(state)
}

fn step_down<N, S, T>(state: &mut WorkerState<N, S, T>)
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
{
    state.set_role(Role::Follower);
    state.votes_received.clear();
    state.leader = None;
    state.reset_election_timer();
}

fn try_advance_commit_index<N, S, T>(state: &mut WorkerState<N, S, T>) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
{
    let Some(majority_floor) = state.match_index_majority_floor() else {
        return Ok(());
    };
    if majority_floor <= state.meta.commit_index {
        return Ok(());
    }
    let entry_term = state.storage.term_at(majority_floor)?;
    if entry_term != Some(state.meta.current_term) {
        return Ok(());
    }
    state.meta.commit_index = majority_floor;
    state.meta.last_applied = state.meta.last_applied.max(majority_floor);
    state.storage.commit_batch(WriteBatch {
        meta: Some(state.meta.clone()),
        ..Default::default()
    })?;
    state.fire_apply_notification();
    Ok(())
}

fn send_heartbeats<N, S, T>(state: &mut WorkerState<N, S, T>) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
{
    let term = state.meta.current_term;
    let me = state.cfg.me;
    let leader_last_index = state.storage.last_index();
    let leader_commit = state.meta.commit_index;
    let snap_idx = state.storage.snap_last_index();
    let snap_term = state.storage.snap_last_term();

    let leader = match state.leader.as_ref() {
        Some(l) => l.clone(),
        None => return Ok(()),
    };

    for peer in state.cfg.members.iter().copied() {
        if peer == me {
            continue;
        }
        let next_idx = leader.next_index.get(&peer).copied().unwrap_or(1);

        // Snapshot fallback: peer is behind the snap pointer.
        if next_idx <= snap_idx && snap_idx > 0 {
            let snapshot = state.storage.read_state().unwrap_or_default();
            let req = InstallSnapshotReq {
                leader: me,
                term,
                last_included_index: snap_idx,
                last_included_term: snap_term,
                snapshot,
            };
            let transport = state.transport.clone();
            let inbox_tx = state.inbox_tx.clone();
            thread::spawn(move || {
                if let Ok(resp) = transport.send_install(peer, req) {
                    let _ = inbox_tx.send(RaftMsg::InstallSnapshotResponse {
                        from: peer,
                        resp,
                        last_included_index: snap_idx,
                    });
                }
            });
            continue;
        }

        let prev_log_index = next_idx.saturating_sub(1);
        let prev_log_term = state.storage.term_at(prev_log_index)?.unwrap_or(0);
        let entries = if next_idx <= leader_last_index {
            state.storage.entries(next_idx, leader_last_index)?
        } else {
            Vec::new()
        };

        let req = AppendEntriesReq {
            leader: me,
            term,
            prev_log_index,
            prev_log_term,
            leader_commit,
            entries,
        };
        let transport = state.transport.clone();
        let inbox_tx = state.inbox_tx.clone();
        thread::spawn(move || {
            if let Ok(resp) = transport.send_append(peer, req) {
                let _ = inbox_tx.send(RaftMsg::AppendResponse { from: peer, resp });
            }
        });
    }

    let _ = try_compact(state);

    state.election_deadline =
        Instant::now() + Duration::from_millis(state.cfg.heartbeat_interval_ms);
    Ok(())
}

fn try_compact<N, S, T>(state: &mut WorkerState<N, S, T>) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
{
    let leader = match state.leader.as_ref() {
        Some(l) => l,
        None => return Ok(()),
    };
    let mut floor = state.storage.last_index();
    for v in leader.match_index.values() {
        floor = floor.min(*v);
    }
    let snap = state.storage.snap_last_index();
    if floor <= snap || floor.saturating_sub(snap) < COMPACT_HYSTERESIS {
        return Ok(());
    }
    let term_at_floor = match state.storage.term_at(floor)? {
        Some(t) => t,
        None => return Ok(()),
    };
    state.meta.snap_last_index = floor;
    state.meta.snap_last_term = term_at_floor;
    state.storage.commit_batch(WriteBatch {
        compact_to: Some((floor, term_at_floor)),
        meta: Some(state.meta.clone()),
        ..Default::default()
    })?;
    Ok(())
}

fn start_election<N, S, T>(state: &mut WorkerState<N, S, T>) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
{
    state.set_role(Role::Candidate);
    state.meta.current_term += 1;
    state.meta.voted_for = Some(state.cfg.me);
    state.storage.commit_batch(WriteBatch {
        meta: Some(state.meta.clone()),
        ..Default::default()
    })?;
    state.votes_received.clear();
    state.votes_received.insert(state.cfg.me);

    let term = state.meta.current_term;
    let me = state.cfg.me;
    let last_log_index = state.storage.last_index();
    let last_log_term = state.storage.last_term();

    for peer in state.cfg.members.iter().copied() {
        if peer == me {
            continue;
        }
        let req = RequestVoteReq {
            candidate: me,
            term,
            last_log_index,
            last_log_term,
        };
        let transport = state.transport.clone();
        let inbox_tx = state.inbox_tx.clone();
        thread::spawn(move || {
            if let Ok(resp) = transport.send_vote(peer, req) {
                let _ = inbox_tx.send(RaftMsg::VoteResponse { from: peer, resp });
            }
        });
    }

    if state.votes_received.len() >= state.quorum() {
        become_leader(state)?;
    } else {
        state.reset_election_timer();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::storage::MemStorage;
    use crate::transport::test_helpers::RecordingTransport;

    fn cfg(me: u16, members: Vec<u16>) -> Config<u16> {
        Config {
            me,
            members,
            election_timeout_ms: (5_000, 10_000),
            heartbeat_interval_ms: 500,
            propose_timeout_ms: 5_000,
            replication_id: [0u8; 32],
        }
    }

    #[test]
    fn worker_starts_in_follower_role() {
        let storage = MemStorage::<u16>::new();
        let transport = Arc::new(RecordingTransport::default());
        let worker = Worker::spawn(
            storage,
            transport,
            cfg(0xAAAA, alloc::vec![0xAAAA, 0xBBBB, 0xCCCC]),
            None,
        );
        let h = worker.handler();
        let snap = h.snapshot().expect("worker alive");
        assert_eq!(snap.role, Role::Follower);
        assert_eq!(snap.current_term, 0);
        assert_eq!(snap.voted_for, None);
        assert_eq!(snap.last_log_index, 0);
        worker.shutdown();
    }

    #[test]
    fn solo_cluster_self_elects_and_proposes() {
        let storage = MemStorage::<u16>::new();
        let transport = Arc::new(RecordingTransport::default());
        let mut cfg = cfg(0xAAAA, alloc::vec![0xAAAA]);
        cfg.election_timeout_ms = (10, 30);
        let worker = Worker::spawn(storage, transport, cfg, None);
        let h = worker.handler();

        // Wait for self-election.
        let until = std::time::Instant::now() + Duration::from_millis(500);
        loop {
            if let Some(s) = h.snapshot() {
                if s.role == Role::Leader { break; }
            }
            assert!(std::time::Instant::now() < until, "no leadership");
            std::thread::sleep(Duration::from_millis(5));
        }

        let idx = h.propose(alloc::vec![1, 2, 3]).expect("propose");
        assert_eq!(idx, 1);
        let snap = h.snapshot().unwrap();
        assert_eq!(snap.role, Role::Leader);
        assert_eq!(snap.last_log_index, 1);
        // Single-node quorum advances commit immediately.
        assert_eq!(snap.commit_index, 1);
        assert_eq!(snap.last_applied, 1);

        worker.shutdown();
    }

    #[test]
    fn follower_accepts_heartbeat_and_advances_term() {
        let storage = MemStorage::<u16>::new();
        let transport = Arc::new(RecordingTransport::default());
        let worker = Worker::spawn(
            storage,
            transport,
            cfg(0xAAAA, alloc::vec![0xAAAA, 0xBBBB, 0xCCCC]),
            None,
        );
        let h = worker.handler();
        let resp = h.handle_inbound_append(
            0xBBBB,
            AppendEntriesReq {
                leader: 0xBBBB,
                term: 5,
                prev_log_index: 0,
                prev_log_term: 0,
                leader_commit: 0,
                entries: alloc::vec![],
            },
        );
        assert!(resp.success);
        assert_eq!(resp.term, 5);
        let snap = h.snapshot().unwrap();
        assert_eq!(snap.current_term, 5);
        worker.shutdown();
    }
}
