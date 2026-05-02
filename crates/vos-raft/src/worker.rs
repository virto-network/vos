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
//!    state machine via the `handle_*_response` paths.
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
    PreVoteReq, PreVoteResp, RequestVoteReq, RequestVoteResp,
};
use crate::storage::{Storage, WriteBatch};
use crate::transport::Transport;

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

/// Reasons a [`WorkerHandle::read_index`] can fail.
///
/// `read_index` is the leader's linearizable-read primitive: it
/// returns the leader's `commit_index` once a quorum of
/// followers has confirmed leadership at the current term. The
/// caller then waits for its own apply progress to reach that
/// index before serving the read.
#[derive(Debug)]
#[non_exhaustive]
pub enum ReadIndexError {
    /// This worker isn't a leader. Address the cluster's leader
    /// instead.
    NotLeader,
    /// We were leader at request time but stepped down before a
    /// quorum could confirm. Caller should retry against the new
    /// leader.
    LeaderStepped,
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
    /// Highest log index that has been compacted into the
    /// snapshot. `0` when no compaction has happened yet.
    pub snap_last_index: u64,
}

/// Inbound message processed by the worker loop.
///
/// `#[non_exhaustive]` on the enum so we can grow new RPC kinds
/// (e.g., a future `PreVote`, learner-add/remove, leader-transfer)
/// without breaking callers. The variant payloads include
/// `oneshot::Sender<…>` from `futures-channel`, so the enum
/// itself is internal protocol — most code should not match on
/// it directly. Use `WorkerHandle::handle_inbound_*` /
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
    PreVote {
        from: N,
        req: PreVoteReq<N>,
        reply: oneshot::Sender<PreVoteResp>,
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
    /// Linearizable-read index request. Resolves to the leader's
    /// `commit_index` after a heartbeat round to quorum confirms
    /// leadership at the current term.
    ReadIndex {
        reply: oneshot::Sender<Result<u64, ReadIndexError>>,
    },
    QueryState {
        reply: oneshot::Sender<WorkerSnapshot<N>>,
    },
    Shutdown,
}

/// Sender half of the worker inbox. Cheap to clone.
///
/// Opaque newtype around the underlying channel sender. Hidden
/// so future commits can swap the channel impl
/// (`futures-channel::mpsc` today, possibly an `embassy_sync`
/// MPMC or a no_std-friendly `MsgSink` trait later) without
/// breaking SemVer. Construct via [`Worker::handler`] /
/// [`WorkerHandle::sender`]; the only public operations are
/// [`Inbox::send`] and `Clone`.
pub struct Inbox<N: NodeId> {
    inner: fmpsc::UnboundedSender<RaftMsg<N>>,
}

impl<N: NodeId> Clone for Inbox<N> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl<N: NodeId> Inbox<N> {
    /// Send a message into the worker. `Err` only if the worker
    /// has shut down (the receiver has been dropped).
    pub fn send(&self, msg: RaftMsg<N>) -> Result<(), RaftMsg<N>> {
        self.inner
            .unbounded_send(msg)
            .map_err(|e| e.into_inner())
    }
}

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
    /// Set to `true` by the worker thread if `run_worker`
    /// returned `Err` (which today means
    /// `Storage::load_meta` failed at init). Read via
    /// [`Worker::init_failed`] — gives the host a yes/no
    /// signal that init succeeded; the `Err`'s payload isn't
    /// surfaced (would require carrying `S::Error` in the
    /// `Worker` type parameter).
    init_failed: Arc<core::sync::atomic::AtomicBool>,
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
    /// deterministic simulators or embedded users with a custom
    /// notification channel.
    ///
    /// **NOTE — this helper drives the worker future on
    /// `futures-executor::block_on`, which has no timer driver.**
    /// Clocks whose `Sleep` future requires an external runtime
    /// (e.g. `TokioClock`'s `tokio::time::Sleep`) will panic on
    /// the first poll. For tokio hosts use
    /// [`spawn_with_tokio_runtime`](Self::spawn_with_tokio_runtime).
    /// For Embassy / async-std / smol hosts, call
    /// [`run_worker`] directly under your own executor.
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
        let init_failed = Arc::new(core::sync::atomic::AtomicBool::new(false));
        let init_failed_for_thread = init_failed.clone();
        let join = std::thread::Builder::new()
            .name(alloc::format!("raft-worker-{:?}", cfg.me))
            .spawn(move || {
                let res = futures_executor::block_on(run_worker(
                    storage,
                    transport,
                    cfg,
                    rx,
                    apply_sink,
                    clock,
                    rng,
                    role_for_thread,
                ));
                if res.is_err() {
                    init_failed_for_thread
                        .store(true, core::sync::atomic::Ordering::Release);
                }
            })
            .expect("spawn raft worker");
        Self {
            inbox: Inbox { inner: tx },
            role,
            join: Some(join),
            init_failed,
        }
    }

    /// Like [`spawn_with`] but drives the worker on a
    /// dedicated tokio current-thread runtime (with the timer
    /// driver enabled). Required when using
    /// [`TokioClock`](crate::TokioClock), whose `Sleep` future
    /// can't be polled on `futures-executor`.
    ///
    /// Requires the `tokio` feature.
    ///
    /// [`spawn_with`]: Self::spawn_with
    #[cfg(feature = "tokio")]
    pub fn spawn_with_tokio_runtime<S, T, C, R, A>(
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
        let init_failed = Arc::new(core::sync::atomic::AtomicBool::new(false));
        let init_failed_for_thread = init_failed.clone();
        let join = std::thread::Builder::new()
            .name(alloc::format!("raft-worker-{:?}", cfg.me))
            .spawn(move || {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                    .expect("build tokio current-thread runtime for raft worker");
                let res = rt.block_on(run_worker(
                    storage,
                    transport,
                    cfg,
                    rx,
                    apply_sink,
                    clock,
                    rng,
                    role_for_thread,
                ));
                if res.is_err() {
                    init_failed_for_thread
                        .store(true, core::sync::atomic::Ordering::Release);
                }
            })
            .expect("spawn raft worker");
        Self {
            inbox: Inbox { inner: tx },
            role,
            join: Some(join),
            init_failed,
        }
    }

    /// `true` if the worker thread exited with an init failure
    /// (today: `Storage::load_meta` returned `Err`). Lock-free
    /// atomic read; reading after a brief idle window is the
    /// reliable check.
    ///
    /// `false` either means init succeeded OR the worker is
    /// still running. To distinguish, also check
    /// [`Worker::role`] or `snapshot()` — a successfully-started
    /// worker reports a real role; a never-started one returns
    /// `Follower` from the atomic mirror but its inbox is dead.
    pub fn init_failed(&self) -> bool {
        self.init_failed
            .load(core::sync::atomic::Ordering::Acquire)
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

#[cfg(feature = "std")]
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
            .send(RaftMsg::QueryState { reply: tx })
            .ok()?;
        rx.await.ok()
    }

    /// Append a new payload to the cluster log.
    pub async fn propose(&self, payload: Vec<u8>) -> Result<u64, ProposeError<()>> {
        let (tx, rx) = oneshot::channel();
        self.inbox
            .send(RaftMsg::Propose { payload, reply: tx })
            .map_err(|_| ProposeError::NotLeader)?;
        rx.await.unwrap_or(Err(ProposeError::NotLeader))
    }

    /// Request a linearizable-read index from the leader.
    ///
    /// On success, returns an index `R` such that any read of
    /// the state machine at or above `last_applied >= R` is
    /// linearizable: reflects every write committed before this
    /// call was issued, and never sees data from a future
    /// term's leader.
    ///
    /// Protocol (Ongaro thesis §6.4):
    /// 1. Worker captures `R = commit_index` at request entry.
    /// 2. Worker triggers a heartbeat round. Once a quorum of
    ///    followers ACKs at the current term — observable as
    ///    `match_index_majority_floor >= R` — the worker
    ///    resolves the request with `Ok(R)`.
    /// 3. If the worker steps down to Follower before quorum
    ///    confirms, resolves with `Err(LeaderStepped)`.
    ///
    /// **Caveat**: this v0.1 impl skips the
    /// "no-op-append-on-leader-promotion" guard. A freshly
    /// elected leader that hasn't yet committed any entry in
    /// its current term may serve a read from a stale prior-term
    /// state. In practice this only matters for the brief
    /// window between leader promotion and first commit; if your
    /// caller waits for any propose to succeed before issuing
    /// `read_index`, the window is closed.
    pub async fn read_index(&self) -> Result<u64, ReadIndexError> {
        let (tx, rx) = oneshot::channel();
        self.inbox
            .send(RaftMsg::ReadIndex { reply: tx })
            .map_err(|_| ReadIndexError::NotLeader)?;
        rx.await.unwrap_or(Err(ReadIndexError::NotLeader))
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
            .send(RaftMsg::AppendEntries { from, req, reply: tx })
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
            .send(RaftMsg::RequestVote { from, req, reply: tx })
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

    /// Inbound `PreVote` from a would-be candidate. Replies
    /// `vote_granted = true` only if our log is at least as
    /// stale as the requester's claimed log AND we haven't
    /// heard from a leader recently. Does NOT mutate
    /// `voted_for` or `current_term`.
    pub async fn handle_inbound_prevote(
        &self,
        from: N,
        req: PreVoteReq<N>,
    ) -> PreVoteResp {
        let (tx, rx) = oneshot::channel();
        let term = req.next_term;
        if self
            .inbox
            .send(RaftMsg::PreVote { from, req, reply: tx })
            .is_err()
        {
            return PreVoteResp { term, vote_granted: false };
        }
        rx.await.unwrap_or(PreVoteResp { term, vote_granted: false })
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
            .send(RaftMsg::InstallSnapshot { from, req, reply: tx })
            .is_err()
        {
            return InstallSnapshotResp { term, bytes_received: 0 };
        }
        rx.await.unwrap_or(InstallSnapshotResp { term, bytes_received: 0 })
    }
}

// ── Internal state ──────────────────────────────────────────

/// Per-follower replication bookkeeping.
#[derive(Debug, Clone)]
struct LeaderState<N: NodeId> {
    next_index: BTreeMap<N, u64>,
    match_index: BTreeMap<N, u64>,
    /// Per-peer in-flight chunked snapshot tracker. Present while
    /// the leader is streaming chunks of a particular
    /// `(last_included_index, last_included_term)` identity to
    /// that peer; cleared on completion or on identity change
    /// (e.g., if the leader has compacted past the in-flight
    /// snapshot's index, it abandons the older stream and starts
    /// a new one). The `offset` field is the byte position of
    /// the next chunk to send.
    snapshot_send: BTreeMap<N, SnapshotSendState>,
}

#[derive(Debug, Clone, Copy)]
struct SnapshotSendState {
    last_included_index: u64,
    last_included_term: u64,
    offset: u64,
}

/// Follower-side accumulator for a chunked `InstallSnapshot`.
struct IncomingSnapshot<N: NodeId> {
    /// Leader from whom the chunks are arriving. A different
    /// leader's first chunk discards this buffer.
    leader: N,
    /// Term of the leader sending the chunks. A higher term in
    /// any follow-up RPC discards this buffer.
    term: u64,
    last_included_index: u64,
    last_included_term: u64,
    /// Accumulated bytes (offsets `0..buffer.len()`).
    buffer: alloc::vec::Vec<u8>,
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
            snapshot_send: BTreeMap::new(),
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
    PreVote {
        from: N,
        next_term: u64,
        result: Option<PreVoteResp>,
    },
    Install {
        from: N,
        result: Option<InstallSnapshotResp>,
        last_included_index: u64,
        last_included_term: u64,
        /// Byte offset of *this* chunk + bytes sent. The leader
        /// uses the response's `bytes_received` against this to
        /// decide whether to advance the cursor or back off.
        chunk_end_offset: u64,
        /// Whether this chunk was the final one. The response
        /// handler only treats the install as complete (and
        /// bumps `match_index` to `last_included_index`) when
        /// `was_final = true`.
        was_final: bool,
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
    /// Wall-clock instant of the most recent successful
    /// AppendEntries receipt from a current-term leader. `None`
    /// until the first heartbeat lands. Used by the pre-vote
    /// leader-check (refuse pre-vote only when we've heard from
    /// a leader recently — distinct from "election deadline is
    /// in the future", which is true for any fresh follower).
    last_heartbeat_received: Option<C::Instant>,
    votes_received: BTreeSet<N>,
    leader: Option<LeaderState<N>>,
    /// In-flight `read_index` requests waiting for a quorum
    /// confirmation. Each entry is `(read_index_at_request, reply)`
    /// — the index becomes resolvable once
    /// `match_index_majority_floor >= read_index_at_request`
    /// (a quorum has acked at the current term, and that ack
    /// landed at or after the request was queued).
    pending_read_index: Vec<(u64, oneshot::Sender<Result<u64, ReadIndexError>>)>,
    /// Follower-side accumulator for an in-flight chunked
    /// `InstallSnapshot`. `None` between snapshot streams; `Some`
    /// while chunks are arriving for a particular `(last_included_index,
    /// last_included_term)` identity. A new identity from the
    /// same leader supersedes the buffer; a stale identity is
    /// rejected as a no-op.
    incoming_snapshot: Option<IncomingSnapshot<N>>,
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

/// Run a worker future to completion.
///
/// Returns `Ok(())` on `RaftMsg::Shutdown` or when the inbox
/// sender is dropped (clean termination). Returns `Err(_)` if
/// the initial `Storage::load_meta` call fails — the worker
/// can't safely start without its persisted meta state. Hosts
/// using [`Worker::spawn`] / [`Worker::spawn_with_tokio_runtime`]
/// can read the result via [`Worker::join_result`].
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
) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
{
    let meta = storage.load_meta().await?;
    let mut state = WorkerState {
        storage,
        transport,
        cfg,
        role: Role::Follower,
        meta,
        election_deadline: clock.now(),
        last_heartbeat_received: None,
        votes_received: BTreeSet::new(),
        pending_read_index: Vec::new(),
        incoming_snapshot: None,
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
                        Some(other) => handle_msg(&mut state, &mut pending, other).await,
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
                        Some(other) => handle_msg(&mut state, &mut pending, other).await,
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
    Ok(())
}

async fn handle_msg<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
    pending: &mut FuturesUnordered<RpcFut<N>>,
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
        RaftMsg::PreVote { from, req, reply } => {
            let resp = handle_request_prevote(state, from, req);
            let _ = reply.send(resp);
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
        RaftMsg::ReadIndex { reply } => {
            handle_read_index(state, pending, reply).await;
        }
        RaftMsg::QueryState { reply } => {
            let _ = reply.send(WorkerSnapshot {
                role: state.role,
                current_term: state.meta.current_term,
                voted_for: state.meta.voted_for,
                last_log_index: state.storage.last_index(),
                commit_index: state.meta.commit_index,
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
        // Follower whose timer expired: start the pre-election
        // phase (or skip it if `cfg.pre_vote == false`).
        Role::Follower => {
            if state.cfg.pre_vote {
                let _ = start_pre_election(state, pending).await;
            } else {
                let _ = start_election(state, pending).await;
            }
        }
        // PreCandidate whose timer expired: pre-election round
        // didn't get quorum within the timeout. Reset and try
        // another pre-vote round (fresh randomized timer
        // prevents lockstep).
        Role::PreCandidate => {
            let _ = start_pre_election(state, pending).await;
        }
        // Candidate whose timer expired: send the real
        // RequestVote round. Either we're here freshly-promoted
        // from PreCandidate (term bump + self-vote happen
        // inside `start_election`), or we already started this
        // term's election and the timeout expired without
        // quorum.
        Role::Candidate => {
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
        RpcOutcome::PreVote {
            from,
            next_term,
            result: Some(resp),
        } => {
            let _ = handle_prevote_response(state, from, next_term, resp).await;
        }
        RpcOutcome::Install {
            from,
            result: Some(resp),
            last_included_index,
            last_included_term,
            chunk_end_offset,
            was_final,
        } => {
            let _ = handle_install_snapshot_response(
                state,
                from,
                resp,
                last_included_index,
                last_included_term,
                chunk_end_offset,
                was_final,
            )
            .await;
        }
        // Transport returned Err — treat as no answer.
        RpcOutcome::Append { .. }
        | RpcOutcome::Vote { .. }
        | RpcOutcome::PreVote { .. }
        | RpcOutcome::Install { .. } => {}
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
    let was_leader = state.role == Role::Leader;
    state.set_role(Role::Follower);
    state.votes_received.clear();
    state.leader = None;
    if was_leader {
        drain_pending_reads_on_step_down(state);
    }
    state.reset_election_timer();
    // We've heard from a current-term leader — record it for
    // the pre-vote leader-check.
    state.last_heartbeat_received = Some(state.clock.now());

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
    let appends: Vec<LogEntry<N>> = req
        .entries
        .iter()
        .enumerate()
        .skip(already_present)
        .map(|(i, e)| LogEntry {
            index: req.prev_log_index + 1 + i as u64,
            term: e.term,
            kind: e.kind.clone(),
        })
        .collect();

    let last_new_index = req.prev_log_index + req.entries.len() as u64;
    let mut commit_advanced = false;
    if req.leader_commit > state.meta.commit_index {
        let new_commit = req.leader_commit.min(last_new_index);
        if new_commit > state.meta.commit_index {
            state.meta.commit_index = new_commit;
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

/// Inbound `PreVote` handler. Critically, this MUST NOT mutate
/// `current_term` or `voted_for` — we answer the hypothetical
/// "would you vote for me at `next_term`?" without committing.
///
/// Refuses if (1) the requester's `next_term` isn't actually
/// higher than ours, (2) we've heard from a current-term leader
/// within `election_timeout_ms.0` (the leader-check that gives
/// pre-vote its term-stability property), or (3) the requester's
/// log is staler than ours (Raft §5.4.1).
fn handle_request_prevote<N, S, T, C, R, A>(
    state: &WorkerState<N, S, T, C, R, A>,
    _from: N,
    req: PreVoteReq<N>,
) -> PreVoteResp
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
{
    if req.next_term <= state.meta.current_term {
        return PreVoteResp {
            term: state.meta.current_term,
            vote_granted: false,
        };
    }
    let now = state.clock.now();
    if let Some(last_hb) = state.last_heartbeat_received {
        let stale_threshold = state.clock.add(
            last_hb,
            core::time::Duration::from_millis(state.cfg.election_timeout_ms.0),
        );
        if now < stale_threshold {
            return PreVoteResp {
                term: state.meta.current_term,
                vote_granted: false,
            };
        }
    }
    let our_last_term = state.storage.last_term();
    let our_last_index = state.storage.last_index();
    let up_to_date = (req.last_log_term > our_last_term)
        || (req.last_log_term == our_last_term && req.last_log_index >= our_last_index);
    PreVoteResp {
        term: state.meta.current_term,
        vote_granted: up_to_date,
    }
}

async fn handle_install_snapshot<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
    from: N,
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
    // Stale-term sender: refuse without touching state.
    if req.term < state.meta.current_term {
        return Ok(InstallSnapshotResp {
            term: state.meta.current_term,
            bytes_received: 0,
        });
    }
    if req.term > state.meta.current_term {
        state.meta.current_term = req.term;
        state.meta.voted_for = None;
        // Drop any in-flight snapshot from a prior term — its
        // identity is now stale.
        state.incoming_snapshot = None;
    }
    let was_leader = state.role == Role::Leader;
    state.set_role(Role::Follower);
    state.votes_received.clear();
    state.leader = None;
    if was_leader {
        drain_pending_reads_on_step_down(state);
    }
    state.reset_election_timer();
    state.last_heartbeat_received = Some(state.clock.now());

    // Snapshot already covered by our local snap pointer — no-op.
    // Drop any in-flight buffer for it too.
    if req.last_included_index <= state.storage.snap_last_index() {
        state.incoming_snapshot = None;
        state
            .storage
            .commit_batch(WriteBatch {
                meta: Some(state.meta.clone()),
                ..Default::default()
            })
            .await?;
        return Ok(InstallSnapshotResp {
            term: state.meta.current_term,
            bytes_received: 0,
        });
    }

    // ── Chunk assembly ──
    //
    // Reset the buffer if the identity changed (different
    // leader, different (idx, term), or no buffer yet).
    let identity_match = state.incoming_snapshot.as_ref().is_some_and(|s| {
        s.leader == from
            && s.term == req.term
            && s.last_included_index == req.last_included_index
            && s.last_included_term == req.last_included_term
    });
    if !identity_match {
        state.incoming_snapshot = Some(IncomingSnapshot {
            leader: from,
            term: req.term,
            last_included_index: req.last_included_index,
            last_included_term: req.last_included_term,
            buffer: Vec::new(),
        });
    }

    let buf = state
        .incoming_snapshot
        .as_mut()
        .expect("set above");
    let current_len = buf.buffer.len() as u64;

    // Out-of-order or duplicate chunk handling:
    // - offset == current_len  → in-order, append.
    // - offset <  current_len  → duplicate / overlap; ignore the
    //   data and report `bytes_received = current_len` so the
    //   leader can resume.
    // - offset >  current_len  → gap; refuse and ask the leader
    //   to resume from `current_len`.
    if req.offset > current_len {
        return Ok(InstallSnapshotResp {
            term: state.meta.current_term,
            bytes_received: current_len,
        });
    }
    if req.offset == current_len {
        buf.buffer.extend_from_slice(&req.data);
    }
    // (offset < current_len: silently treat as already-have.)

    let new_len = buf.buffer.len() as u64;

    // Not the final chunk — wait for more.
    if !req.done {
        return Ok(InstallSnapshotResp {
            term: state.meta.current_term,
            bytes_received: new_len,
        });
    }

    // Final chunk — commit the assembled snapshot atomically.
    let snapshot = state
        .incoming_snapshot
        .take()
        .expect("set above")
        .buffer;

    state.meta.snap_last_index = req.last_included_index;
    state.meta.snap_last_term = req.last_included_term;
    state.meta.commit_index = state.meta.commit_index.max(req.last_included_index);

    state
        .storage
        .commit_batch(WriteBatch {
            compact_to: Some((req.last_included_index, req.last_included_term)),
            state: Some(snapshot),
            meta: Some(state.meta.clone()),
            ..Default::default()
        })
        .await?;

    state.fire_apply_notification();
    Ok(InstallSnapshotResp {
        term: state.meta.current_term,
        bytes_received: new_len,
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
        // Quorum match-index may have advanced past the captured
        // commit_index of one or more pending read_index
        // requests. Resolve any that meet the threshold.
        try_resolve_pending_reads(state).await;
    } else {
        let cur = leader.next_index.get(&from).copied().unwrap_or(1);
        let new_next = cur.saturating_sub(1).max(1);
        leader.next_index.insert(from, new_next);
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn handle_install_snapshot_response<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
    from: N,
    resp: InstallSnapshotResp,
    last_included_index: u64,
    last_included_term: u64,
    chunk_end_offset: u64,
    was_final: bool,
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
    let Some(leader) = state.leader.as_mut() else {
        return Ok(());
    };

    // Update the per-peer chunk cursor. The follower's
    // `bytes_received` is authoritative — if it tells us it
    // has fewer bytes than we sent (lost chunk, identity reset
    // on its side), we resume from there.
    let cursor = resp.bytes_received.min(chunk_end_offset);
    let entry = leader
        .snapshot_send
        .entry(from)
        .or_insert(SnapshotSendState {
            last_included_index,
            last_included_term,
            offset: 0,
        });
    if entry.last_included_index == last_included_index
        && entry.last_included_term == last_included_term
    {
        entry.offset = entry.offset.max(cursor);
    } else {
        // Identity differs — the leader has compacted past this
        // stream's index, so start a new tracker on next send.
        leader.snapshot_send.remove(&from);
    }

    if was_final && resp.bytes_received >= chunk_end_offset {
        // Follower acknowledged the full snapshot. Bump match/
        // next_index and clear the per-peer tracker so the next
        // heartbeat resumes log-based replication.
        let prev_match = leader.match_index.get(&from).copied().unwrap_or(0);
        if last_included_index > prev_match {
            leader.match_index.insert(from, last_included_index);
        }
        leader.next_index.insert(from, last_included_index + 1);
        leader.snapshot_send.remove(&from);
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

/// Outcome handler for a `PreVote` reply. On quorum-yes,
/// transitions PreCandidate → Candidate and collapses the
/// election deadline so the next `on_timer` fires
/// `start_election` immediately.
async fn handle_prevote_response<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
    from: N,
    next_term: u64,
    resp: PreVoteResp,
) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
{
    // A peer at a strictly higher term tells us we're stale.
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
    // Stale next_term or wrong role.
    if state.role != Role::PreCandidate
        || next_term != state.meta.current_term + 1
    {
        return Ok(());
    }
    if resp.vote_granted {
        state.votes_received.insert(from);
        if state.votes_received.len() >= state.quorum() {
            // Pre-vote quorum reached. Promote to Candidate and
            // collapse the timer; `on_timer`'s next fire will
            // call `start_election` which bumps the term and
            // sends real RequestVotes.
            state.set_role(Role::Candidate);
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
    let entry = LogEntry::data(new_index, term, payload);
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

/// Handle a `RaftMsg::ReadIndex` request. Captures the leader's
/// current `commit_index`, queues the request on
/// `pending_read_index`, and triggers an immediate heartbeat
/// round so a fresh quorum confirmation arrives soon. The
/// request resolves once `match_index_majority_floor` reaches
/// the captured commit_index.
async fn handle_read_index<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
    pending: &mut FuturesUnordered<RpcFut<N>>,
    reply: oneshot::Sender<Result<u64, ReadIndexError>>,
) where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
{
    if state.role != Role::Leader {
        let _ = reply.send(Err(ReadIndexError::NotLeader));
        return;
    }
    // Solo cluster: no peers to confirm with, but the leader IS
    // the only voter. Resolve immediately.
    if state.cfg.members.len() <= 1 {
        let _ = reply.send(Ok(state.meta.commit_index));
        return;
    }
    let r = state.meta.commit_index;
    state.pending_read_index.push((r, reply));
    // Trigger a fresh heartbeat round. The round's quorum-success
    // confirms we're still leader at the current term; the
    // resulting match_index advance fires
    // `try_resolve_pending_reads` which drains the queue.
    let _ = send_heartbeats(state, pending).await;
}

/// Drain `pending_read_index` entries whose captured commit
/// index is now ≤ `match_index_majority_floor`. Each drained
/// entry is replied with `Ok(R)`.
async fn try_resolve_pending_reads<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
) where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
{
    if state.pending_read_index.is_empty() {
        return;
    }
    let Some(mf) = state.match_index_majority_floor().await else {
        return;
    };
    // Partition pending into resolvable + still-waiting.
    let mut still_waiting = Vec::new();
    for (r, reply) in core::mem::take(&mut state.pending_read_index) {
        if r <= mf {
            let _ = reply.send(Ok(r));
        } else {
            still_waiting.push((r, reply));
        }
    }
    state.pending_read_index = still_waiting;
}

/// Drain every pending read-index entry with a `LeaderStepped`
/// error. Called by `step_down`.
fn drain_pending_reads_on_step_down<N, S, T, C, R, A>(
    state: &mut WorkerState<N, S, T, C, R, A>,
) where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
{
    for (_r, reply) in core::mem::take(&mut state.pending_read_index) {
        let _ = reply.send(Err(ReadIndexError::LeaderStepped));
    }
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
    drain_pending_reads_on_step_down(state);
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
            // Resume from the per-peer cursor if it points at the
            // current snap identity; otherwise restart from byte 0.
            let resume_offset = state
                .leader
                .as_ref()
                .and_then(|l| l.snapshot_send.get(&peer).copied())
                .filter(|s| {
                    s.last_included_index == snap_idx
                        && s.last_included_term == snap_term
                })
                .map(|s| s.offset)
                .unwrap_or(0);

            let snapshot = state.storage.read_state().await.unwrap_or_default();
            let total_len = snapshot.len() as u64;
            // Cap chunk size, but never produce a 0-byte non-final
            // chunk (would loop forever). For an empty snapshot
            // we send a single done=true chunk with zero bytes.
            let chunk_max = state
                .cfg
                .install_snapshot_chunk_bytes
                .max(1);
            let start = resume_offset.min(total_len) as usize;
            let end = (start + chunk_max).min(snapshot.len());
            let chunk: Vec<u8> = snapshot[start..end].to_vec();
            let chunk_end_offset = end as u64;
            let was_final = chunk_end_offset >= total_len;

            // Update / install our local cursor BEFORE sending so
            // a same-tick second peer resume picks the same value.
            if let Some(leader_mut) = state.leader.as_mut() {
                leader_mut.snapshot_send.insert(
                    peer,
                    SnapshotSendState {
                        last_included_index: snap_idx,
                        last_included_term: snap_term,
                        offset: resume_offset,
                    },
                );
            }

            let req = InstallSnapshotReq {
                leader: me,
                term,
                last_included_index: snap_idx,
                last_included_term: snap_term,
                offset: resume_offset,
                done: was_final,
                data: chunk,
            };
            let transport = state.transport.clone();
            let fut: RpcFut<N> = Box::pin(async move {
                let result = transport.send_install(peer, req).await.ok();
                RpcOutcome::Install {
                    from: peer,
                    result,
                    last_included_index: snap_idx,
                    last_included_term: snap_term,
                    chunk_end_offset,
                    was_final,
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
    if floor <= snap || floor.saturating_sub(snap) < state.cfg.compact_hysteresis {
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

/// Pre-election phase. Sets role to `PreCandidate`, sends
/// `PreVote` to every peer asking "would you grant a real vote
/// at `current_term + 1`?". Does NOT bump `current_term` or
/// persist `voted_for`. On quorum-yes (handled in
/// `handle_prevote_response`), promotes to Candidate and
/// `on_timer` fires `start_election` next.
///
/// Solo cluster (members.len() <= 1): self-vote alone is the
/// quorum; skip pre-vote and go straight to `start_election`.
async fn start_pre_election<N, S, T, C, R, A>(
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
    if state.cfg.members.len() <= 1 {
        return start_election(state, pending).await;
    }
    state.set_role(Role::PreCandidate);
    state.votes_received.clear();
    state.votes_received.insert(state.cfg.me);

    let next_term = state.meta.current_term + 1;
    let me = state.cfg.me;
    let last_log_index = state.storage.last_index();
    let last_log_term = state.storage.last_term();

    for peer in state.cfg.members.iter().copied() {
        if peer == me {
            continue;
        }
        let req = PreVoteReq {
            candidate: me,
            next_term,
            last_log_index,
            last_log_term,
        };
        let transport = state.transport.clone();
        let fut: RpcFut<N> = Box::pin(async move {
            let result = transport.send_prevote(peer, req).await.ok();
            RpcOutcome::PreVote {
                from: peer,
                next_term,
                result,
            }
        });
        pending.push(fut);
    }

    state.reset_election_timer();
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
            if let Some(s) = block_on(h.snapshot())
                && s.role == Role::Leader
            {
                break;
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

    /// Multi-entry truncation: a follower's tail conflicts with the
    /// leader's batch starting at the *first* entry, so all
    /// pre-existing entries must be dropped. Single-entry truncation
    /// is exercised by `follower_truncates_conflicting_tail_then_appends`
    /// in vos's facade tests; this verifies the ≥2-entry conflict
    /// path doesn't have an off-by-one in the truncate-from index.
    #[test]
    fn follower_truncates_multiple_entries_at_root_conflict() {
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

        // Seed the follower with three entries at term 1.
        let r1 = block_on(h.handle_inbound_append(
            0xBBBB,
            AppendEntriesReq {
                leader: 0xBBBB,
                term: 1,
                prev_log_index: 0,
                prev_log_term: 0,
                leader_commit: 0,
                entries: alloc::vec![
                    LogEntry::data(1, 1, alloc::vec![1]),
                    LogEntry::data(2, 1, alloc::vec![1]),
                    LogEntry::data(3, 1, alloc::vec![1]),
                ],
            },
        ));
        assert!(r1.success);
        let snap = block_on(h.snapshot()).unwrap();
        assert_eq!(snap.last_log_index, 3);

        // Higher-term leader sends three NEW entries at the same
        // indices — every existing entry diverges from the first.
        // The follower must drop all three and graft the new ones.
        let r2 = block_on(h.handle_inbound_append(
            0xCCCC,
            AppendEntriesReq {
                leader: 0xCCCC,
                term: 2,
                prev_log_index: 0,
                prev_log_term: 0,
                leader_commit: 0,
                entries: alloc::vec![
                    LogEntry::data(1, 2, alloc::vec![2]),
                    LogEntry::data(2, 2, alloc::vec![2]),
                    LogEntry::data(3, 2, alloc::vec![2]),
                ],
            },
        ));
        assert!(r2.success);
        let snap = block_on(h.snapshot()).unwrap();
        assert_eq!(snap.last_log_index, 3);
        assert_eq!(snap.current_term, 2);
        worker.shutdown();
    }

    /// Snapshot install where `last_included_index > last_log_index`:
    /// a stale follower whose log is far behind the leader's snap
    /// pointer. The follower drops everything, sets snap pointer +
    /// last_index to the leader's value, replaces state row.
    #[test]
    fn snapshot_install_past_last_log_index() {
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

        // Fresh follower (last_log_index = 0). Leader installs a
        // snapshot at index 100.
        let resp = block_on(h.handle_inbound_install(
            0xBBBB,
            InstallSnapshotReq {
                leader: 0xBBBB,
                term: 5,
                last_included_index: 100,
                last_included_term: 4,
                offset: 0,
                done: true,
                data: alloc::vec![0xAA; 32],
            },
        ));
        assert_eq!(resp.term, 5);
        assert_eq!(resp.bytes_received, 32);
        let snap = block_on(h.snapshot()).unwrap();
        assert_eq!(snap.snap_last_index, 100);
        assert_eq!(snap.commit_index, 100);
        // last_log_index follows the snap pointer when the live
        // log is empty (per `MemStorage::last_index` fallback).
        assert_eq!(snap.last_log_index, 100);
        worker.shutdown();
    }

    /// Vote rejected because the candidate's log is less up-to-date
    /// than the follower's. Raft §5.4.1: a follower refuses if its
    /// own last entry has a higher term, or the same term with a
    /// higher index.
    #[test]
    fn vote_refused_when_candidate_log_is_stale() {
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

        // Seed the follower's log with one entry at term 5.
        let r = block_on(h.handle_inbound_append(
            0xBBBB,
            AppendEntriesReq {
                leader: 0xBBBB,
                term: 5,
                prev_log_index: 0,
                prev_log_term: 0,
                leader_commit: 0,
                entries: alloc::vec![LogEntry::data(1, 5, alloc::vec![1])],
            },
        ));
        assert!(r.success);

        // Candidate at term 6 with a stale log (last_log_term=2,
        // way behind our term 5). Refused.
        let r = block_on(h.handle_inbound_vote(
            0xCCCC,
            RequestVoteReq {
                candidate: 0xCCCC,
                term: 6,
                last_log_index: 99, // even though the index is high…
                last_log_term: 2,   // …the term is below ours.
            },
        ));
        assert!(!r.vote_granted, "stale-log candidate must be refused");
        // Term still updates (§5.1: bumps on RequestVote at higher term).
        assert_eq!(r.term, 6);

        // Same-term-but-shorter-log: also refused.
        let r = block_on(h.handle_inbound_vote(
            0xCCCC,
            RequestVoteReq {
                candidate: 0xCCCC,
                term: 7,
                last_log_index: 0,
                last_log_term: 5,
            },
        ));
        assert!(!r.vote_granted, "shorter-log-same-term candidate must be refused");
        worker.shutdown();
    }

    /// At-most-one-vote-per-term, more rigorously: the same
    /// candidate asking twice at the same term must get the same
    /// answer (idempotent grant), but the second grant must NOT
    /// re-bump `voted_for` or fire a fresh persist. A
    /// DIFFERENT candidate asking at the same term must be
    /// refused — only one candidate per term ever wins our vote.
    ///
    /// The existing proptest property checks only two DIFFERENT
    /// candidates; this test pins the same-candidate-twice
    /// case so a future regression that mistakenly granted
    /// duplicates would be caught at the unit level.
    #[test]
    fn at_most_one_vote_per_term_handles_same_candidate_twice() {
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

        // First vote: granted to candidate 0xBBBB at term 4.
        let r1 = block_on(h.handle_inbound_vote(
            0xBBBB,
            RequestVoteReq {
                candidate: 0xBBBB,
                term: 4,
                last_log_index: 0,
                last_log_term: 0,
            },
        ));
        assert!(r1.vote_granted);
        let snap1 = block_on(h.snapshot()).unwrap();
        assert_eq!(snap1.voted_for, Some(0xBBBB));
        assert_eq!(snap1.current_term, 4);

        // SAME candidate asks again at the SAME term — idempotent
        // grant. The receiver may re-grant (since voted_for ==
        // candidate), but voted_for / current_term must be
        // unchanged.
        let r2 = block_on(h.handle_inbound_vote(
            0xBBBB,
            RequestVoteReq {
                candidate: 0xBBBB,
                term: 4,
                last_log_index: 0,
                last_log_term: 0,
            },
        ));
        assert!(
            r2.vote_granted,
            "same-candidate re-ask at same term must be granted (idempotent)",
        );
        let snap2 = block_on(h.snapshot()).unwrap();
        assert_eq!(
            snap2.voted_for,
            Some(0xBBBB),
            "voted_for must still point at the same candidate after re-ask",
        );
        assert_eq!(snap2.current_term, 4);

        // DIFFERENT candidate at SAME term — refused. This is
        // the actual safety property: at most one candidate per
        // term wins.
        let r3 = block_on(h.handle_inbound_vote(
            0xCCCC,
            RequestVoteReq {
                candidate: 0xCCCC,
                term: 4,
                last_log_index: 0,
                last_log_term: 0,
            },
        ));
        assert!(
            !r3.vote_granted,
            "different candidate at the same term must be refused — \
             only one vote per term",
        );
        let snap3 = block_on(h.snapshot()).unwrap();
        assert_eq!(
            snap3.voted_for,
            Some(0xBBBB),
            "voted_for must NOT have been overwritten by the rejected RequestVote",
        );

        worker.shutdown();
    }

    /// Duplicate `InstallSnapshot` delivery (same `req` twice
    /// in a row) must be idempotent: snap pointer doesn't move
    /// past the second call's `last_included_index`, the state
    /// row isn't double-written, the term is adopted only once.
    ///
    /// The cluster-level `cluster_converges_under_full_duplication`
    /// integration test never actually exercises this path
    /// because it doesn't trigger compaction (5 entries,
    /// hysteresis 16). This unit test pins the receiver-side
    /// idempotence directly.
    #[test]
    fn install_snapshot_is_idempotent_on_duplicate_delivery() {
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

        // First install: term 7, last_included_index 50,
        // last_included_term 6, snapshot bytes 0xAA…
        let req = || InstallSnapshotReq {
            leader: 0xBBBB,
            term: 7,
            last_included_index: 50,
            last_included_term: 6,
            offset: 0,
            done: true,
            data: alloc::vec![0xAA; 16],
        };

        let r1 = block_on(h.handle_inbound_install(0xBBBB, req()));
        assert_eq!(r1.term, 7);
        let snap1 = block_on(h.snapshot()).unwrap();
        assert_eq!(snap1.snap_last_index, 50);
        assert_eq!(snap1.commit_index, 50);
        assert_eq!(snap1.current_term, 7);

        // Duplicate delivery — same RPC bits. The receiver hits
        // the `req.last_included_index <= snap_last_index`
        // idempotent branch and no-ops.
        let r2 = block_on(h.handle_inbound_install(0xBBBB, req()));
        assert_eq!(r2.term, 7);
        let snap2 = block_on(h.snapshot()).unwrap();
        assert_eq!(
            snap2.snap_last_index, 50,
            "duplicate install must not move the snap pointer",
        );
        assert_eq!(
            snap2.commit_index, 50,
            "duplicate install must not double-bump commit_index",
        );
        assert_eq!(snap2.current_term, 7);

        // Triple-check: the same install at a LOWER index also
        // no-ops (already covered by `install_snapshot_at_lower_index_is_no_op`
        // in vos's facade tests, but worth re-asserting here).
        let r3 = block_on(h.handle_inbound_install(
            0xBBBB,
            InstallSnapshotReq {
                leader: 0xBBBB,
                term: 7,
                last_included_index: 30,
                last_included_term: 5,
                offset: 0,
                done: true,
                data: alloc::vec![0xBB; 8],
            },
        ));
        assert_eq!(r3.term, 7);
        let snap3 = block_on(h.snapshot()).unwrap();
        assert_eq!(
            snap3.snap_last_index, 50,
            "lower-index install must not regress the snap pointer",
        );

        worker.shutdown();
    }
}
