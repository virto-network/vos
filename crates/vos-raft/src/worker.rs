//! Per-replication-group Raft worker — async, runtime-agnostic.
//!
//! The worker is a single async future that loops over four
//! signal sources via `futures::select!`:
//!
//! 1. **Inbox** (`futures_channel::mpsc::UnboundedReceiver`) —
//!    [`RaftMsg`] messages from external callers (RPC handlers,
//!    proposes, snapshot queries, shutdown).
//! 2. **Election timer** ([`Clock::sleep_until`]) — fires when
//!    the current `election_deadline` expires; promotes a
//!    Follower to Candidate or makes a Leader send heartbeats.
//! 3. **In-flight outbound RPCs** (`FuturesUnordered`) — every
//!    `transport.send_*()` future the worker emits parks here
//!    until the peer (or the transport's own timeout) replies.
//!    Completed futures inject their results back into the
//!    state machine via [`handle_*_response`] paths.
//! 4. **Cooperative yield** — none required; the loop is
//!    naturally yielding because every storage / transport call
//!    is async.
//!
//! No threads spawned. No runtime selected. The host driving
//! this future picks the executor (tokio, embassy, async-std,
//! a deterministic simulator). The std-feature
//! [`Worker::spawn`] convenience runs the future on a dedicated
//! thread using the `futures-executor` crate as a tiny
//! single-task executor — fine for vos's use case but not
//! mandatory.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicU8, Ordering};
use core::time::Duration;

use futures_channel::mpsc as fmpsc;
use futures_channel::oneshot;
use futures_util::stream::{FuturesUnordered, StreamExt};
use futures_util::FutureExt;

use crate::clock::{ApplySink, Clock, Rng};
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

/// Hysteresis for the leader's auto-compaction. The worker only
/// compacts when the eligible-up-to-index is at least this many
/// entries past the current snap pointer; otherwise we'd open a
/// write txn on every heartbeat tick to drop a single entry.
pub const COMPACT_HYSTERESIS: u64 = 16;

/// Reasons a [`WorkerHandle::propose`] can fail.
///
/// `#[non_exhaustive]` because new failure modes (timeout,
/// channel-closed, fatal-storage-error) will land in minor
/// versions; callers should match with a wildcard.
#[derive(Debug)]
#[non_exhaustive]
pub enum ProposeError<E> {
    /// This worker is currently `Follower` or `Candidate`. The
    /// caller must retry against the cluster's leader.
    NotLeader,
    /// Storage write failed on the append.
    Storage(E),
}

/// Diagnostic snapshot of a worker's state.
///
/// `#[non_exhaustive]` because future commits will surface
/// additional state (leader-hint, in-flight RPCs) — construction
/// is internal-only and consumers should always match with `..`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkerSnapshot<N: NodeId> {
    pub role: Role,
    pub current_term: u64,
    pub voted_for: Option<N>,
    pub last_log_index: u64,
    pub commit_index: u64,
    pub last_applied: u64,
    /// Highest log index that has been compacted into the
    /// snapshot. `0` when no compaction has happened yet.
    /// Useful for proptest invariants that need to assert the
    /// snap pointer never regresses.
    pub snap_last_index: u64,
}

/// Inbound message processed by the worker loop.
///
/// `#[non_exhaustive]` on the enum so we can grow new RPC kinds
/// (e.g., a future `PreVote`, learner-add/remove, leader-transfer)
/// without breaking callers. The variant payloads include
/// `oneshot::Sender<…>` from `futures-channel`, so the enum
/// itself is internal protocol — most code should not match on
/// it directly. Use [`WorkerHandle::handle_inbound_*`] /
/// [`WorkerHandle::propose`] instead.
#[allow(dead_code)]
#[non_exhaustive]
pub enum RaftMsg<N: NodeId> {
    AppendEntries {
        from: N,
        req: AppendEntriesReq<N>,
        reply: oneshot::Sender<AppendEntriesResp>,
    },
    RequestVote {
        from: N,
        req: RequestVoteReq<N>,
        reply: oneshot::Sender<RequestVoteResp>,
    },
    InstallSnapshot {
        from: N,
        req: InstallSnapshotReq<N>,
        reply: oneshot::Sender<InstallSnapshotResp>,
    },
    /// Append a new entry to the leader's log.
    Propose {
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<u64, ProposeError<()>>>,
    },
    QueryState {
        reply: oneshot::Sender<WorkerSnapshot<N>>,
    },
    Shutdown,
}

/// Sender half of the worker inbox. Cheap to clone.
pub type Inbox<N> = fmpsc::UnboundedSender<RaftMsg<N>>;

// ── std-only spawn helper ───────────────────────────────────

/// Owning handle to a worker driven on a dedicated std thread.
/// Drop or [`shutdown`] cleans up.
///
/// Embedded hosts skip this and call [`run_worker`] directly on
/// their own executor.
///
/// [`shutdown`]: Self::shutdown
#[cfg(feature = "std")]
pub struct Worker<N: NodeId> {
    inbox: Inbox<N>,
    role: Arc<AtomicU8>,
    join: Option<std::thread::JoinHandle<()>>,
}

#[cfg(feature = "std")]
impl<N: NodeId> Worker<N> {
    /// Spawn a worker thread for one replication group, driven
    /// by a [`StdClock`](crate::StdClock) +
    /// [`StdRng`](crate::StdRng). The thread runs a single-task
    /// `futures_executor::block_on` over the worker future.
    ///
    /// `apply_notifier` is the historical std-only convenience: a
    /// `None` suppresses commit notifications (sink = `()`) and
    /// `Some(sender)` plugs the channel directly into the worker.
    /// For embedded use or custom sinks, call
    /// [`spawn_with`](Self::spawn_with) and pass any
    /// [`ApplySink`].
    pub fn spawn<S, T>(
        storage: S,
        transport: Arc<T>,
        cfg: Config<N>,
        apply_notifier: Option<std::sync::mpsc::Sender<u64>>,
    ) -> Self
    where
        S: Storage<N>,
        T: Transport<N>,
    {
        // Translate the historical Option<Sender> into the
        // generic ApplySink at the call site so the inner
        // `spawn_with` signature stays uniform.
        match apply_notifier {
            Some(tx) => Self::spawn_with(
                storage,
                transport,
                cfg,
                tx,
                crate::clock::StdClock,
                crate::clock::StdRng::from_entropy(),
            ),
            None => Self::spawn_with(
                storage,
                transport,
                cfg,
                (),
                crate::clock::StdClock,
                crate::clock::StdRng::from_entropy(),
            ),
        }
    }

    /// Like [`spawn`](Self::spawn) but with caller-supplied
    /// [`Clock`], [`Rng`], and [`ApplySink`]. Useful for
    /// deterministic simulators, hosts that want to plug in
    /// `tokio::time` directly, or embedded users with a custom
    /// notification channel.
    pub fn spawn_with<S, T, C, R, A>(
        storage: S,
        transport: Arc<T>,
        cfg: Config<N>,
        apply_sink: A,
        clock: C,
        rng: R,
    ) -> Self
    where
        S: Storage<N>,
        T: Transport<N>,
        C: Clock,
        R: Rng,
        A: ApplySink,
    {
        let (tx, rx) = fmpsc::unbounded();
        let role = Arc::new(AtomicU8::new(Role::Follower.as_u8()));
        let role_for_thread = role.clone();
        let join = std::thread::Builder::new()
            .name(alloc::format!("raft-worker-{:?}", cfg.me))
            .spawn(move || {
                futures_executor::block_on(run_worker(
                    storage,
                    transport,
                    cfg,
                    rx,
                    apply_sink,
                    clock,
                    rng,
                    role_for_thread,
                ));
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
        let _ = self.inbox.unbounded_send(RaftMsg::Shutdown);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

#[cfg(feature = "std")]
impl<N: NodeId> Drop for Worker<N> {
    fn drop(&mut self) {
        let _ = self.inbox.unbounded_send(RaftMsg::Shutdown);
        if let Some(j) = self.join.take() {
            let _ = j.join();
        }
    }
}

/// Cheap-to-clone handle for sending messages into the worker.
#[derive(Clone)]
pub struct WorkerHandle<N: NodeId> {
    inbox: Inbox<N>,
    role: Arc<AtomicU8>,
}

impl<N: NodeId> WorkerHandle<N> {
    /// Lock-free read of the worker's current role.
    pub fn role(&self) -> Role {
        Role::from_u8(self.role.load(Ordering::Relaxed))
    }

    /// Cheap-to-clone sender for spawning helper tasks.
    pub fn sender(&self) -> Inbox<N> {
        self.inbox.clone()
    }

    /// Diagnostic snapshot of the worker's current state.
    /// `None` if the worker is shut down.
    pub async fn snapshot(&self) -> Option<WorkerSnapshot<N>> {
        let (tx, rx) = oneshot::channel();
        self.inbox
            .unbounded_send(RaftMsg::QueryState { reply: tx })
            .ok()?;
        rx.await.ok()
    }

    /// Append a new payload to the cluster log.
    pub async fn propose(&self, payload: Vec<u8>) -> Result<u64, ProposeError<()>> {
        let (tx, rx) = oneshot::channel();
        self.inbox
            .unbounded_send(RaftMsg::Propose { payload, reply: tx })
            .map_err(|_| ProposeError::NotLeader)?;
        rx.await.unwrap_or(Err(ProposeError::NotLeader))
    }

    /// Inbound `AppendEntries` from a peer.
    pub async fn handle_inbound_append(
        &self,
        from: N,
        req: AppendEntriesReq<N>,
    ) -> AppendEntriesResp {
        let (tx, rx) = oneshot::channel();
        let term = req.term;
        if self
            .inbox
            .unbounded_send(RaftMsg::AppendEntries { from, req, reply: tx })
            .is_err()
        {
            return AppendEntriesResp {
                term,
                success: false,
                match_index: 0,
            };
        }
        rx.await.unwrap_or(AppendEntriesResp {
            term,
            success: false,
            match_index: 0,
        })
    }

    /// Inbound `RequestVote` from a peer.
    pub async fn handle_inbound_vote(
        &self,
        from: N,
        req: RequestVoteReq<N>,
    ) -> RequestVoteResp {
        let (tx, rx) = oneshot::channel();
        let term = req.term;
        if self
            .inbox
            .unbounded_send(RaftMsg::RequestVote { from, req, reply: tx })
            .is_err()
        {
            return RequestVoteResp {
                term,
                vote_granted: false,
            };
        }
        rx.await.unwrap_or(RequestVoteResp {
            term,
            vote_granted: false,
        })
    }

    /// Inbound `InstallSnapshot` from a peer.
    pub async fn handle_inbound_install(
        &self,
        from: N,
        req: InstallSnapshotReq<N>,
    ) -> InstallSnapshotResp {
        let (tx, rx) = oneshot::channel();
        let term = req.term;
        if self
            .inbox
            .unbounded_send(RaftMsg::InstallSnapshot { from, req, reply: tx })
            .is_err()
        {
            return InstallSnapshotResp { term };
        }
        rx.await.unwrap_or(InstallSnapshotResp { term })
    }
}

// ── Internal state ──────────────────────────────────────────

/// Per-follower replication bookkeeping.
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

/// Outbound RPC future result. Each variant is what the worker
/// would have received over the inbox in the pre-async design;
/// here we just pull it straight from the future.
enum RpcOutcome<N: NodeId> {
    Append {
        from: N,
        result: Option<AppendEntriesResp>,
    },
    Vote {
        from: N,
        result: Option<RequestVoteResp>,
    },
    Install {
        from: N,
        result: Option<InstallSnapshotResp>,
        last_included_index: u64,
    },
}

/// In-flight RPC future. Driven by [`FuturesUnordered`] inside
/// the main loop's `select!`.
type RpcFut<N> = Pin<Box<dyn Future<Output = RpcOutcome<N>> + Send>>;

struct WorkerState<N, S, T, C, R, A>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
{
    storage: S,
    transport: Arc<T>,
    cfg: Config<N>,
    role: Role,
    meta: Meta<N>,
    election_deadline: C::Instant,
    votes_received: BTreeSet<N>,
    leader: Option<LeaderState<N>>,
    apply_sink: A,
    role_atomic: Arc<AtomicU8>,
    clock: C,
    rng: R,
}

impl<N, S, T, C, R, A> WorkerState<N, S, T, C, R, A>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    A: ApplySink,
    R: Rng,
    A: ApplySink,
{
    fn publish_role(&self) {
        self.role_atomic
            .store(self.role.as_u8(), Ordering::Relaxed);
    }

    fn set_role(&mut self, role: Role) {
        self.role = role;
        self.publish_role();
    }

    fn fire_apply_notification(&self) {
        self.apply_sink.notify(self.meta.commit_index);
    }

    fn reset_election_timer(&mut self) {
        let (lo, hi) = self.cfg.election_timeout_ms;
        let span = (hi.saturating_sub(lo)).max(1);
        let r = self.rng.next_u64();
        let me_seed = {
            use core::hash::{Hash, Hasher};
            // A trivial FNV-ish hash so we don't pull stdlib's
            // DefaultHasher (which lives in std::collections).
            // Quality requirements are mild — just per-peer
            // separation of jitter.
            struct Fnv(u64);
            impl Hasher for Fnv {
                fn finish(&self) -> u64 {
                    self.0
                }
                fn write(&mut self, bytes: &[u8]) {
                    for b in bytes {
                        self.0 = self.0.wrapping_mul(1099511628211);
                        self.0 ^= u64::from(*b);
                    }
                }
            }
            let mut h = Fnv(0xCBF29CE484222325);
            <N as Hash>::hash(&self.cfg.me, &mut h);
            h.finish()
        };
        let jitter = (r ^ me_seed ^ self.meta.current_term) % span;
        let timeout = Duration::from_millis(lo + jitter);
        self.election_deadline = self.clock.add(self.clock.now(), timeout);
    }

    fn quorum(&self) -> usize {
        self.cfg.quorum()
    }

    async fn match_index_majority_floor(&self) -> Option<u64> {
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

// ── Public driver ───────────────────────────────────────────

/// Run a worker future to completion. Returns when the inbox
/// receives a `RaftMsg::Shutdown` or the inbox sender is dropped.
///
/// Embedded hosts call this directly inside their executor.
/// Std hosts typically use [`Worker::spawn`].
#[allow(clippy::too_many_arguments)]
pub async fn run_worker<N, S, T, C, R, A>(
    storage: S,
    transport: Arc<T>,
    cfg: Config<N>,
    inbox_rx: fmpsc::UnboundedReceiver<RaftMsg<N>>,
    apply_sink: A,
    clock: C,
    rng: R,
    role_atomic: Arc<AtomicU8>,
) where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
{
    let meta = match storage.load_meta().await {
        Ok(m) => m,
        Err(_) => return,
    };
    let mut state = WorkerState {
        storage,
        transport,
        cfg,
        role: Role::Follower,
        meta,
        election_deadline: clock.now(),
        votes_received: BTreeSet::new(),
        leader: None,
        apply_sink,
        role_atomic,
        clock,
        rng,
    };
    state.reset_election_timer();
    state.publish_role();

    let mut inbox_rx = inbox_rx;
    let mut pending: FuturesUnordered<RpcFut<N>> = FuturesUnordered::new();

    loop {
        // The select! macro's timer arm needs a fused future.
        // `clock.sleep_until(deadline)` returns C::Sleep — wrap
        // it with `.fuse()` so it's safe to poll past completion
        // (FuturesUnordered already hands us fused items).
        let timer = state.clock.sleep_until(state.election_deadline).fuse();
        futures_util::pin_mut!(timer);

        let next_inbox = inbox_rx.next().fuse();
        futures_util::pin_mut!(next_inbox);

        // CRITICAL: `FuturesUnordered::next()` resolves
        // `Ready(None)` *immediately* when the set is empty.
        // Including it as a select! arm during the (common)
        // intervals when no outbound RPCs are in flight produces a
        // 100%-CPU spin — every iteration the empty-set arm fires,
        // we ignore the `None`, loop, fire again. Branch on
        // `pending.is_empty()` to drop the arm entirely in that
        // case so the select! parks on timer + inbox.
        if pending.is_empty() {
            futures_util::select! {
                msg = next_inbox => {
                    match msg {
                        Some(RaftMsg::Shutdown) => break,
                        Some(other) => handle_msg(&mut state, other).await,
                        None => break,
                    }
                }
                _ = timer => {
                    on_timer(&mut state, &mut pending).await;
                }
            }
        } else {
            let next_pending = pending.next().fuse();
            futures_util::pin_mut!(next_pending);
            futures_util::select! {
                msg = next_inbox => {
                    match msg {
                        Some(RaftMsg::Shutdown) => break,
                        Some(other) => handle_msg(&mut state, other).await,
                        None => break,
                    }
                }
                _ = timer => {
                    on_timer(&mut state, &mut pending).await;
                }
                outcome = next_pending => {
                    if let Some(o) = outcome {
                        handle_rpc_outcome(&mut state, o).await;
                    }
                }
            }
        }
    }
}

async fn handle_msg<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
    msg: RaftMsg<N>,
) where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
{
    match msg {
        RaftMsg::AppendEntries { from, req, reply } => {
            if let Ok(resp) = handle_append_entries(state, from, req).await {
                let _ = reply.send(resp);
            }
        }
        RaftMsg::RequestVote { from, req, reply } => {
            if let Ok(resp) = handle_request_vote(state, from, req).await {
                let _ = reply.send(resp);
            }
        }
        RaftMsg::InstallSnapshot { from, req, reply } => {
            if let Ok(resp) = handle_install_snapshot(state, from, req).await {
                let _ = reply.send(resp);
            }
        }
        RaftMsg::Propose { payload, reply } => {
            let r = handle_propose(state, payload).await;
            let _ = reply.send(r);
        }
        RaftMsg::QueryState { reply } => {
            let _ = reply.send(WorkerSnapshot {
                role: state.role,
                current_term: state.meta.current_term,
                voted_for: state.meta.voted_for,
                last_log_index: state.storage.last_index(),
                commit_index: state.meta.commit_index,
                last_applied: state.meta.last_applied,
                snap_last_index: state.storage.snap_last_index(),
            });
        }
        RaftMsg::Shutdown => unreachable!("handled in run_worker"),
    }
}

async fn on_timer<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
    pending: &mut FuturesUnordered<RpcFut<N>>,
) where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
{
    match state.role {
        Role::Follower | Role::Candidate => {
            let _ = start_election(state, pending).await;
        }
        Role::Leader => {
            let _ = send_heartbeats(state, pending).await;
        }
    }
}

async fn handle_rpc_outcome<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
    outcome: RpcOutcome<N>,
) where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
{
    match outcome {
        RpcOutcome::Append {
            from,
            result: Some(resp),
        } => {
            let _ = handle_append_response(state, from, resp).await;
        }
        RpcOutcome::Vote {
            from,
            result: Some(resp),
        } => {
            let _ = handle_vote_response(state, from, resp).await;
        }
        RpcOutcome::Install {
            from,
            result: Some(resp),
            last_included_index,
        } => {
            let _ =
                handle_install_snapshot_response(state, from, resp, last_included_index).await;
        }
        // Transport returned Err — treat as no answer.
        RpcOutcome::Append { .. } | RpcOutcome::Vote { .. } | RpcOutcome::Install { .. } => {}
    }
}

// ── Inbound RPC handlers ────────────────────────────────────

async fn handle_append_entries<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
    _from: N,
    req: AppendEntriesReq<N>,
) -> Result<AppendEntriesResp, S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
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

    let our_prev_term = state.storage.term_at(req.prev_log_index).await?;
    let consistent = our_prev_term == Some(req.prev_log_term);
    if !consistent {
        state
            .storage
            .commit_batch(WriteBatch {
                meta: Some(state.meta.clone()),
                ..Default::default()
            })
            .await?;
        return Ok(AppendEntriesResp {
            term: state.meta.current_term,
            success: false,
            match_index: 0,
        });
    }

    let mut conflict_at: Option<u64> = None;
    let mut already_present = 0usize;
    for (i, e) in req.entries.iter().enumerate() {
        let idx = req.prev_log_index + 1 + i as u64;
        match state.storage.term_at(idx).await? {
            Some(t) if t == e.term => already_present += 1,
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

    state
        .storage
        .commit_batch(WriteBatch {
            truncate_after,
            compact_to: None,
            appends,
            state: None,
            meta: Some(state.meta.clone()),
        })
        .await?;

    if commit_advanced {
        state.fire_apply_notification();
    }

    Ok(AppendEntriesResp {
        term: state.meta.current_term,
        success: true,
        match_index: last_new_index,
    })
}

async fn handle_request_vote<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
    _from: N,
    req: RequestVoteReq<N>,
) -> Result<RequestVoteResp, S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
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
        state
            .storage
            .commit_batch(WriteBatch {
                meta: Some(state.meta.clone()),
                ..Default::default()
            })
            .await?;
    }

    Ok(RequestVoteResp {
        term: state.meta.current_term,
        vote_granted: granted,
    })
}

async fn handle_install_snapshot<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
    _from: N,
    req: InstallSnapshotReq<N>,
) -> Result<InstallSnapshotResp, S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
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
        state
            .storage
            .commit_batch(WriteBatch {
                meta: Some(state.meta.clone()),
                ..Default::default()
            })
            .await?;
        return Ok(InstallSnapshotResp {
            term: state.meta.current_term,
        });
    }

    state.meta.snap_last_index = req.last_included_index;
    state.meta.snap_last_term = req.last_included_term;
    state.meta.commit_index = state.meta.commit_index.max(req.last_included_index);
    state.meta.last_applied = state.meta.last_applied.max(req.last_included_index);

    state
        .storage
        .commit_batch(WriteBatch {
            compact_to: Some((req.last_included_index, req.last_included_term)),
            state: Some(req.snapshot),
            meta: Some(state.meta.clone()),
            ..Default::default()
        })
        .await?;

    state.fire_apply_notification();
    Ok(InstallSnapshotResp {
        term: state.meta.current_term,
    })
}

// ── Outbound RPC response handlers ──────────────────────────

async fn handle_append_response<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
    from: N,
    resp: AppendEntriesResp,
) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
{
    if resp.term > state.meta.current_term {
        state.meta.current_term = resp.term;
        state.meta.voted_for = None;
        state
            .storage
            .commit_batch(WriteBatch {
                meta: Some(state.meta.clone()),
                ..Default::default()
            })
            .await?;
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
        try_advance_commit_index(state).await?;
    } else {
        let cur = leader.next_index.get(&from).copied().unwrap_or(1);
        let new_next = cur.saturating_sub(1).max(1);
        leader.next_index.insert(from, new_next);
    }
    Ok(())
}

async fn handle_install_snapshot_response<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
    from: N,
    resp: InstallSnapshotResp,
    last_included_index: u64,
) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
{
    if resp.term > state.meta.current_term {
        state.meta.current_term = resp.term;
        state.meta.voted_for = None;
        state
            .storage
            .commit_batch(WriteBatch {
                meta: Some(state.meta.clone()),
                ..Default::default()
            })
            .await?;
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

async fn handle_vote_response<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
    from: N,
    resp: RequestVoteResp,
) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
{
    if resp.term > state.meta.current_term {
        state.meta.current_term = resp.term;
        state.meta.voted_for = None;
        state
            .storage
            .commit_batch(WriteBatch {
                meta: Some(state.meta.clone()),
                ..Default::default()
            })
            .await?;
        step_down(state);
        return Ok(());
    }
    if state.role != Role::Candidate || resp.term != state.meta.current_term {
        return Ok(());
    }
    if resp.vote_granted {
        state.votes_received.insert(from);
        if state.votes_received.len() >= state.quorum() {
            // Become leader. We can't pass `pending` here without
            // major plumbing churn — call become_leader inline,
            // and the next timer tick will fire heartbeats.
            become_leader_no_heartbeat(state).await?;
            // Trigger a heartbeat by collapsing the deadline.
            state.election_deadline = state.clock.now();
        }
    }
    Ok(())
}

// ── Higher-level transitions ────────────────────────────────

async fn handle_propose<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
    payload: Vec<u8>,
) -> Result<u64, ProposeError<()>>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
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
        .await
        .map_err(|_| ProposeError::Storage(()))?;
    let _ = try_advance_commit_index(state).await;
    Ok(new_index)
}

async fn become_leader_no_heartbeat<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
{
    state.set_role(Role::Leader);
    state.votes_received.clear();
    let last = state.storage.last_index();
    state.leader = Some(LeaderState::fresh(&state.cfg.members, state.cfg.me, last));
    Ok(())
}

fn step_down<N, S, T, C, R, A>(state: &mut WorkerState<N, S, T, C, R, A>)
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
{
    state.set_role(Role::Follower);
    state.votes_received.clear();
    state.leader = None;
    state.reset_election_timer();
}

async fn try_advance_commit_index<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
{
    let Some(majority_floor) = state.match_index_majority_floor().await else {
        return Ok(());
    };
    if majority_floor <= state.meta.commit_index {
        return Ok(());
    }
    let entry_term = state.storage.term_at(majority_floor).await?;
    if entry_term != Some(state.meta.current_term) {
        return Ok(());
    }
    state.meta.commit_index = majority_floor;
    state.meta.last_applied = state.meta.last_applied.max(majority_floor);
    state
        .storage
        .commit_batch(WriteBatch {
            meta: Some(state.meta.clone()),
            ..Default::default()
        })
        .await?;
    state.fire_apply_notification();
    Ok(())
}

async fn send_heartbeats<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
    pending: &mut FuturesUnordered<RpcFut<N>>,
) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
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

        if next_idx <= snap_idx && snap_idx > 0 {
            let snapshot = state.storage.read_state().await.unwrap_or_default();
            let req = InstallSnapshotReq {
                leader: me,
                term,
                last_included_index: snap_idx,
                last_included_term: snap_term,
                snapshot,
            };
            let transport = state.transport.clone();
            let fut: RpcFut<N> = Box::pin(async move {
                let result = transport.send_install(peer, req).await.ok();
                RpcOutcome::Install {
                    from: peer,
                    result,
                    last_included_index: snap_idx,
                }
            });
            pending.push(fut);
            continue;
        }

        let prev_log_index = next_idx.saturating_sub(1);
        let prev_log_term = state
            .storage
            .term_at(prev_log_index)
            .await?
            .unwrap_or(0);
        let entries = if next_idx <= leader_last_index {
            state.storage.entries(next_idx, leader_last_index).await?
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
        let fut: RpcFut<N> = Box::pin(async move {
            let result = transport.send_append(peer, req).await.ok();
            RpcOutcome::Append { from: peer, result }
        });
        pending.push(fut);
    }

    let _ = try_compact(state).await;

    // Schedule the next heartbeat.
    state.election_deadline = state
        .clock
        .add(state.clock.now(), Duration::from_millis(state.cfg.heartbeat_interval_ms));
    Ok(())
}

async fn try_compact<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
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
    let term_at_floor = match state.storage.term_at(floor).await? {
        Some(t) => t,
        None => return Ok(()),
    };
    state.meta.snap_last_index = floor;
    state.meta.snap_last_term = term_at_floor;
    state
        .storage
        .commit_batch(WriteBatch {
            compact_to: Some((floor, term_at_floor)),
            meta: Some(state.meta.clone()),
            ..Default::default()
        })
        .await?;
    Ok(())
}

async fn start_election<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
    pending: &mut FuturesUnordered<RpcFut<N>>,
) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
{
    state.set_role(Role::Candidate);
    state.meta.current_term += 1;
    state.meta.voted_for = Some(state.cfg.me);
    state
        .storage
        .commit_batch(WriteBatch {
            meta: Some(state.meta.clone()),
            ..Default::default()
        })
        .await?;
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
        let fut: RpcFut<N> = Box::pin(async move {
            let result = transport.send_vote(peer, req).await.ok();
            RpcOutcome::Vote { from: peer, result }
        });
        pending.push(fut);
    }

    if state.votes_received.len() >= state.quorum() {
        become_leader_no_heartbeat(state).await?;
        // Next loop iteration's timer fires immediately.
        state.election_deadline = state.clock.now();
    } else {
        state.reset_election_timer();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{StdClock, StdRng};
    use crate::storage::MemStorage;
    use crate::transport::test_helpers::RecordingTransport;
    use crate::testutil::block_on;

    fn cfg(me: u16, members: Vec<u16>) -> Config<u16> {
        let mut c = Config::new(me, members, [0u8; 32]);
        c.election_timeout_ms = (5_000, 10_000);
        c.heartbeat_interval_ms = 500;
        c
    }

    #[test]
    fn worker_starts_in_follower_role() {
        let storage = MemStorage::<u16>::new();
        let transport = Arc::new(RecordingTransport::default());
        let worker = Worker::spawn_with(
            storage,
            transport,
            cfg(0xAAAA, alloc::vec![0xAAAA, 0xBBBB, 0xCCCC]),
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        let h = worker.handler();
        let snap = block_on(h.snapshot()).expect("worker alive");
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
        let worker = Worker::spawn_with(
            storage,
            transport,
            cfg,
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        let h = worker.handler();

        let until = std::time::Instant::now() + Duration::from_millis(500);
        loop {
            if let Some(s) = block_on(h.snapshot()) {
                if s.role == Role::Leader {
                    break;
                }
            }
            assert!(std::time::Instant::now() < until, "no leadership");
            std::thread::sleep(Duration::from_millis(5));
        }

        let idx = block_on(h.propose(alloc::vec![1, 2, 3])).expect("propose");
        assert_eq!(idx, 1);
        let snap = block_on(h.snapshot()).unwrap();
        assert_eq!(snap.role, Role::Leader);
        assert_eq!(snap.last_log_index, 1);
        assert_eq!(snap.commit_index, 1);
        assert_eq!(snap.last_applied, 1);

        worker.shutdown();
    }

    #[test]
    fn follower_accepts_heartbeat_and_advances_term() {
        let storage = MemStorage::<u16>::new();
        let transport = Arc::new(RecordingTransport::default());
        let worker = Worker::spawn_with(
            storage,
            transport,
            cfg(0xAAAA, alloc::vec![0xAAAA, 0xBBBB, 0xCCCC]),
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        let h = worker.handler();
        let resp = block_on(h.handle_inbound_append(
            0xBBBB,
            AppendEntriesReq {
                leader: 0xBBBB,
                term: 5,
                prev_log_index: 0,
                prev_log_term: 0,
                leader_commit: 0,
                entries: alloc::vec![],
            },
        ));
        assert!(resp.success);
        assert_eq!(resp.term, 5);
        let snap = block_on(h.snapshot()).unwrap();
        assert_eq!(snap.current_term, 5);
        worker.shutdown();
    }

    /// Regression for the empty-`FuturesUnordered` busy-spin.
    ///
    /// Pre-fix the worker's `select!` polled `pending.next()`
    /// every iteration; an empty `FuturesUnordered::next()`
    /// resolves `Ready(None)` immediately, so the loop never
    /// parked — it burned 100% CPU until a timer or inbox event
    /// happened to win the race.
    ///
    /// We detect a spin by wrapping the clock and counting
    /// `sleep_until` calls. The worker calls it once per loop
    /// iteration to rebuild the timer arm of `select!`, so the
    /// counter doubles as a loop-iteration counter. A parked loop
    /// hits it only when a real event fires (single digits per
    /// 100ms); a spinning loop hits it >10k times per 100ms on a
    /// modern CPU.
    #[test]
    fn idle_worker_does_not_spin_on_empty_pending() {
        use core::sync::atomic::{AtomicU64, Ordering as AO};
        use std::sync::Arc as StdArc;

        #[derive(Clone)]
        struct CountingClock {
            sleep_calls: StdArc<AtomicU64>,
        }
        impl crate::clock::Clock for CountingClock {
            type Instant = std::time::Instant;
            type Sleep = crate::clock::StdSleep;
            fn now(&self) -> Self::Instant {
                std::time::Instant::now()
            }
            fn add(&self, t: Self::Instant, d: Duration) -> Self::Instant {
                t.checked_add(d).unwrap_or(t)
            }
            fn sleep_until(&self, deadline: Self::Instant) -> Self::Sleep {
                self.sleep_calls.fetch_add(1, AO::Relaxed);
                StdClock.sleep_until(deadline)
            }
        }

        let storage = MemStorage::<u16>::new();
        let transport = Arc::new(RecordingTransport::default());
        // Multi-member cluster, RecordingTransport never replies,
        // election timer 10s so it doesn't fire during measurement,
        // and `pending` stays empty (no outbound RPCs queued) for
        // the whole window.
        let mut cfg_idle =
            Config::new(0xAAAA, alloc::vec![0xAAAA, 0xBBBB, 0xCCCC], [0u8; 32]);
        cfg_idle.election_timeout_ms = (10_000, 10_000);
        cfg_idle.heartbeat_interval_ms = 1_000;

        let sleep_calls = StdArc::new(AtomicU64::new(0));
        let clock = CountingClock {
            sleep_calls: sleep_calls.clone(),
        };
        let worker = Worker::spawn_with(
            storage,
            transport,
            cfg_idle,
            (),
            clock,
            StdRng::from_entropy(),
        );

        std::thread::sleep(Duration::from_millis(100));
        let n = sleep_calls.load(AO::Relaxed);
        worker.shutdown();
        // Empirically: ~5 with the fix, ~12_000 in a spin.
        // 10_000 is a wide threshold — any spin lights this up.
        assert!(
            n < 10_000,
            "idle worker called sleep_until {n} times in 100ms — busy-spin regression",
        );
    }
}
