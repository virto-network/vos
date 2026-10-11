//! A driver for one replica: runs the protocol core ([`crate::core::Core`])
//! on an async executor with a [`Storage`], a [`Transport`] and a [`Clock`].
//! It carries out the core's writes in order, sends its messages, loads the
//! entries it asks for, and streams snapshots, which the core leaves to its
//! host. Hosts that drive many groups (the VOS node) drive the core
//! themselves.
//!
//! A storage error stops the worker: the core keeps no rollback, and a write
//! that may have half-happened cannot be retried as if it had not.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU8, Ordering};
use core::time::Duration;

use futures_channel::mpsc as fmpsc;
use futures_channel::oneshot;
use futures_util::FutureExt;
use futures_util::stream::StreamExt;

use crate::clock::{ApplySink, Clock, Rng};
use crate::config::{Config, NodeId};
use crate::core::{Action, Answer, Core, Recovered, SnapshotConfiguration, Status};
pub use crate::core::{ChangeMembershipError, ProposeError, ReadIndexError};
use crate::meta::Meta;
use crate::role::Role;
use crate::rpc::{InstallSnapshotReq, InstallSnapshotResp};
use crate::storage::{Storage, WriteBatch};
use crate::transport::{Envelope, Transport};

/// Diagnostic snapshot of a worker's state.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct WorkerSnapshot<N: NodeId> {
    pub role: Role,
    pub current_term: u64,
    pub voted_for: Option<N>,
    pub last_log_index: u64,
    pub commit_index: u64,
    /// Highest log index compacted into the snapshot; 0 before any.
    pub snap_last_index: u64,
    /// Highest index this replica holds durably.
    pub durable_index: u64,
    /// The member set this replica operates against; during a joint phase
    /// the new set, with `joint_old` the prior one.
    pub members: Vec<N>,
    pub joint_old: Option<Vec<N>>,
    /// Log or snapshot index that established `members` and `joint_old`.
    pub active_config_index: Option<u64>,
    /// The final configuration whose removed voters have not all been
    /// confirmed as notified.
    pub retirement_final_index: Option<u64>,
    /// The leader this replica last heard from at its term.
    pub leader_hint: Option<N>,
}

impl<N: NodeId> From<Status<N>> for WorkerSnapshot<N> {
    fn from(status: Status<N>) -> Self {
        Self {
            role: status.role,
            current_term: status.current_term,
            voted_for: status.voted_for,
            last_log_index: status.last_log_index,
            commit_index: status.commit_index,
            snap_last_index: status.snap_last_index,
            durable_index: status.durable_index,
            members: status.members,
            joint_old: status.joint_old,
            active_config_index: status.active_config_index,
            retirement_final_index: status.retirement_final_index,
            leader_hint: status.leader_hint,
        }
    }
}

/// A message to the worker.
#[non_exhaustive]
pub enum RaftMsg<N: NodeId> {
    /// Something a peer sent.
    Deliver {
        from: N,
        envelope: Envelope<N>,
    },
    Propose {
        payload: Vec<u8>,
        reply: oneshot::Sender<Result<u64, ProposeError>>,
    },
    ReadIndex {
        timeout: Option<Duration>,
        reply: oneshot::Sender<Result<u64, ReadIndexError>>,
    },
    ChangeMembership {
        new_members: Vec<N>,
        reply: oneshot::Sender<Result<u64, ChangeMembershipError>>,
    },
    TransferLeadership {
        to: Option<N>,
    },
    QueryState {
        reply: oneshot::Sender<WorkerSnapshot<N>>,
    },
    Shutdown,
}

/// Sender half of the worker's inbox. Cheap to clone.
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
    /// Send a message into the worker; `Err` once it has stopped.
    #[allow(clippy::result_large_err)]
    pub fn send(&self, msg: RaftMsg<N>) -> Result<(), RaftMsg<N>> {
        self.inner.unbounded_send(msg).map_err(|e| e.into_inner())
    }
}

struct PublishedWorkerStatus<N: NodeId> {
    snapshot: WorkerSnapshot<N>,
    valid_until: std::time::Instant,
}

type SharedWorkerStatus<N> = Arc<std::sync::RwLock<Option<PublishedWorkerStatus<N>>>>;

/// On the worker thread's exit, however it ends: no status, and no role
/// but follower, since a stopped worker leads nothing.
struct ExitGuard<N: NodeId> {
    status: SharedWorkerStatus<N>,
    role: Arc<AtomicU8>,
}

impl<N: NodeId> Drop for ExitGuard<N> {
    fn drop(&mut self) {
        if let Ok(mut status) = self.status.write() {
            *status = None;
        }
        self.role.store(Role::Follower.as_u8(), Ordering::Relaxed);
    }
}

type InitSignal = Arc<(std::sync::Mutex<Option<bool>>, std::sync::Condvar)>;

/// A worker driven on a dedicated thread. Drop or [`shutdown`] stops it.
///
/// [`shutdown`]: Self::shutdown
pub struct Worker<N: NodeId> {
    inbox: Inbox<N>,
    role: Arc<AtomicU8>,
    status: SharedWorkerStatus<N>,
    join: Option<std::thread::JoinHandle<()>>,
    init: InitSignal,
}

impl<N: NodeId> Worker<N> {
    /// Spawn a worker on a thread with a [`StdClock`](crate::StdClock) and
    /// a [`StdRng`](crate::StdRng); `apply_notifier` receives commit
    /// indices.
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

    /// Like [`spawn`](Self::spawn) with a caller's clock, randomness and
    /// apply sink. It runs on `futures-executor`, which has no timer driver:
    /// clocks whose sleeps need a runtime (tokio's) panic on first poll;
    /// use `spawn_with_tokio_runtime` (feature `tokio`).
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
        Self::spawn_on(storage, transport, cfg, apply_sink, clock, rng, |future| {
            let _ = futures_executor::block_on(future);
        })
    }

    /// Like [`spawn_with`](Self::spawn_with), on a tokio current-thread
    /// runtime, as [`TokioClock`](crate::TokioClock) requires.
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
        Self::spawn_on(storage, transport, cfg, apply_sink, clock, rng, |future| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_time()
                .build()
                .expect("build a tokio current-thread runtime for the raft worker");
            let _ = runtime.block_on(future);
        })
    }

    fn spawn_on<S, T, C, R, A, F>(
        storage: S,
        transport: Arc<T>,
        cfg: Config<N>,
        apply_sink: A,
        clock: C,
        rng: R,
        run: F,
    ) -> Self
    where
        S: Storage<N>,
        T: Transport<N>,
        C: Clock,
        R: Rng,
        A: ApplySink,
        F: FnOnce(
                core::pin::Pin<
                    alloc::boxed::Box<dyn core::future::Future<Output = Result<(), S::Error>>>,
                >,
            ) + Send
            + 'static,
    {
        let (tx, rx) = fmpsc::unbounded();
        let role = Arc::new(AtomicU8::new(Role::Follower.as_u8()));
        let role_for_thread = role.clone();
        let status = Arc::new(std::sync::RwLock::new(None));
        let status_for_thread = status.clone();
        let init: InitSignal = Arc::new((std::sync::Mutex::new(None), std::sync::Condvar::new()));
        let init_for_thread = init.clone();
        let join = std::thread::Builder::new()
            .name(alloc::format!("raft-worker-{:?}", cfg.me))
            .spawn(move || {
                let _exit = ExitGuard {
                    status: status_for_thread.clone(),
                    role: role_for_thread.clone(),
                };
                let init_signal = move |ok: bool| {
                    let mut ready = init_for_thread.0.lock().unwrap();
                    *ready = Some(ok);
                    init_for_thread.1.notify_all();
                };
                run(alloc::boxed::Box::pin(run_worker_with_status(
                    storage,
                    transport,
                    cfg,
                    rx,
                    apply_sink,
                    clock,
                    rng,
                    role_for_thread,
                    status_for_thread,
                    init_signal,
                )));
            })
            .expect("spawn raft worker");
        Self {
            inbox: Inbox { inner: tx },
            role,
            status,
            join: Some(join),
            init,
        }
    }

    /// Block until the worker has loaded its store: `Err` if that failed
    /// and the worker stopped.
    #[allow(clippy::result_unit_err)]
    pub fn wait_init(&self) -> Result<(), ()> {
        let mut ready = self.init.0.lock().unwrap();
        while ready.is_none() {
            ready = self.init.1.wait(ready).unwrap();
        }
        if *ready == Some(true) {
            Ok(())
        } else {
            Err(())
        }
    }

    pub fn handler(&self) -> WorkerHandle<N> {
        WorkerHandle {
            inbox: self.inbox.clone(),
            role: self.role.clone(),
            status: self.status.clone(),
        }
    }

    pub fn role(&self) -> Role {
        Role::from_u8(self.role.load(Ordering::Relaxed))
    }

    /// Stop the worker and join its thread.
    pub fn shutdown(mut self) {
        self.stop();
    }

    fn stop(&mut self) {
        let _ = self.inbox.send(RaftMsg::Shutdown);
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

impl<N: NodeId> Drop for Worker<N> {
    fn drop(&mut self) {
        self.stop();
    }
}

/// A cheap-to-clone handle to a worker.
#[derive(Clone)]
pub struct WorkerHandle<N: NodeId> {
    inbox: Inbox<N>,
    role: Arc<AtomicU8>,
    status: SharedWorkerStatus<N>,
}

impl<N: NodeId> WorkerHandle<N> {
    pub fn role(&self) -> Role {
        Role::from_u8(self.role.load(Ordering::Relaxed))
    }

    /// The status published after the worker's last event, without
    /// entering its inbox; `None` once it is stale or the worker stopped.
    pub fn cached_snapshot(&self) -> Option<WorkerSnapshot<N>> {
        let status = self.status.try_read().ok()?;
        let published = status.as_ref()?;
        (published.valid_until > std::time::Instant::now()).then(|| published.snapshot.clone())
    }

    pub fn sender(&self) -> Inbox<N> {
        self.inbox.clone()
    }

    /// The worker's status once it has carried out everything sent to it
    /// before (its writes durable, its answers sent); `None` once it
    /// stopped.
    pub async fn snapshot(&self) -> Option<WorkerSnapshot<N>> {
        let (tx, rx) = oneshot::channel();
        self.inbox.send(RaftMsg::QueryState { reply: tx }).ok()?;
        rx.await.ok()
    }

    /// Hand something a peer sent to the worker.
    pub fn deliver(&self, from: N, envelope: Envelope<N>) {
        let _ = self.inbox.send(RaftMsg::Deliver { from, envelope });
    }

    /// Append `payload`: its index, once in the leader's log.
    pub async fn propose(&self, payload: Vec<u8>) -> Result<u64, ProposeError> {
        let (tx, rx) = oneshot::channel();
        self.inbox
            .send(RaftMsg::Propose { payload, reply: tx })
            .map_err(|_| ProposeError::Stopped)?;
        rx.await.unwrap_or(Err(ProposeError::Stopped))
    }

    /// A linearizable read index: once this replica has applied through it,
    /// a read reflects every write committed before the call.
    pub async fn read_index(&self) -> Result<u64, ReadIndexError> {
        self.read(None).await
    }

    /// As [`Self::read_index`], given up after `timeout` on the worker's
    /// clock.
    pub async fn read_index_with_timeout(&self, timeout: Duration) -> Result<u64, ReadIndexError> {
        self.read(Some(timeout)).await
    }

    async fn read(&self, timeout: Option<Duration>) -> Result<u64, ReadIndexError> {
        let (tx, rx) = oneshot::channel();
        self.inbox
            .send(RaftMsg::ReadIndex { timeout, reply: tx })
            .map_err(|_| ReadIndexError::Stopped)?;
        rx.await.unwrap_or(Err(ReadIndexError::Stopped))
    }

    /// Change membership to `new_members` by joint consensus: the index of
    /// the joint entry.
    pub async fn change_membership(
        &self,
        new_members: Vec<N>,
    ) -> Result<u64, ChangeMembershipError> {
        let (tx, rx) = oneshot::channel();
        self.inbox
            .send(RaftMsg::ChangeMembership {
                new_members,
                reply: tx,
            })
            .map_err(|_| ChangeMembershipError::Stopped)?;
        rx.await.unwrap_or(Err(ChangeMembershipError::Stopped))
    }

    /// Hand leadership to `to`, or to the most up-to-date member.
    pub fn transfer_leadership(&self, to: Option<N>) {
        let _ = self.inbox.send(RaftMsg::TransferLeadership { to });
    }
}

// ── The driver ─────────────────────────────────────────────

/// A snapshot this replica streams to a peer, one chunk in flight.
struct Outgoing<N: NodeId> {
    index: u64,
    term: u64,
    configuration: Option<SnapshotConfiguration<N>>,
    data: Arc<Vec<u8>>,
    /// Bytes the peer acknowledged.
    offset: u64,
    /// When the chunk in flight was sent, on the core's clock.
    sent_at: u64,
}

/// A snapshot this replica is receiving.
struct Incoming<N: NodeId> {
    leader: N,
    term: u64,
    index: u64,
    index_term: u64,
    buffer: Vec<u8>,
}

struct Replies<N: NodeId> {
    next: u64,
    proposals: BTreeMap<u64, oneshot::Sender<Result<u64, ProposeError>>>,
    reads: BTreeMap<u64, oneshot::Sender<Result<u64, ReadIndexError>>>,
    changes: BTreeMap<u64, oneshot::Sender<Result<u64, ChangeMembershipError>>>,
    _node: core::marker::PhantomData<N>,
}

struct Driver<N: NodeId, S, T, A> {
    me: N,
    storage: S,
    transport: Arc<T>,
    apply_sink: A,
    replies: Replies<N>,
    outgoing: BTreeMap<N, Outgoing<N>>,
    incoming: Option<Incoming<N>>,
    status_replies: Vec<oneshot::Sender<WorkerSnapshot<N>>>,
    chunk_bytes: usize,
    max_snapshot_bytes: usize,
    resend_ms: u64,
    now: u64,
}

impl<N, S, T, A> Driver<N, S, T, A>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    A: ApplySink,
{
    fn send(&self, to: N, envelope: Envelope<N>) {
        self.transport.send(self.me, to, envelope);
    }

    fn token(&mut self) -> u64 {
        self.replies.next += 1;
        self.replies.next
    }

    fn handle(&mut self, core: &mut Core<N>, msg: RaftMsg<N>) -> Option<Envelope<N>> {
        match msg {
            RaftMsg::Deliver {
                from,
                envelope: Envelope::Raft(message),
            } => core.receive(from, message),
            RaftMsg::Deliver { envelope, .. } => return Some(envelope),
            RaftMsg::Propose { payload, reply } => {
                let token = self.token();
                self.replies.proposals.insert(token, reply);
                core.propose(token, payload);
            }
            RaftMsg::ReadIndex { timeout, reply } => {
                let token = self.token();
                self.replies.reads.insert(token, reply);
                core.read_index(token, timeout.map(|timeout| timeout.as_millis() as u64));
            }
            RaftMsg::ChangeMembership { new_members, reply } => {
                let token = self.token();
                self.replies.changes.insert(token, reply);
                core.change_membership(token, new_members);
            }
            RaftMsg::TransferLeadership { to } => core.transfer_leadership(to),
            // Answered once the round's actions are carried out.
            RaftMsg::QueryState { reply } => self.status_replies.push(reply),
            RaftMsg::Shutdown => {}
        }
        None
    }

    /// Carry out the core's actions, and those they lead to, in order.
    async fn run_actions(&mut self, core: &mut Core<N>, role: &AtomicU8) -> Result<(), S::Error> {
        loop {
            let actions = core.take_actions();
            if actions.is_empty() {
                return Ok(());
            }
            for action in actions {
                match action {
                    Action::Write(write) => {
                        // Only compaction and a snapshot switch move the
                        // snapshot pointer; a write keeps the store's.
                        let meta = write.meta.map(|meta| Meta {
                            snap_last_index: self.storage.snap_last_index(),
                            snap_last_term: self.storage.snap_last_term(),
                            ..meta
                        });
                        self.storage
                            .commit_batch(WriteBatch {
                                truncate_after: write.truncate_after,
                                compact_to: None,
                                appends: write.entries,
                                state: None,
                                meta,
                                active_config: write.active_config,
                                log_start_config: None,
                            })
                            .await?;
                        core.durable(write.seq);
                        core.entries_durable(write.seq);
                    }
                    Action::Send { to, message } => self.send(to, Envelope::Raft(message)),
                    Action::LoadEntries(load) => {
                        let entries = self.storage.entries(load.from, load.to).await?;
                        core.loaded(load, entries);
                    }
                    Action::Committed { index } => {
                        self.apply_sink.notify(index);
                        let applied = self.storage.applied_index().await?.unwrap_or(index);
                        core.durably_applied(applied);
                    }
                    Action::SendSnapshot {
                        to,
                        index,
                        term,
                        configuration,
                    } => {
                        self.start_snapshot(core, to, index, term, configuration)
                            .await?
                    }
                    Action::CompactBound {
                        through,
                        configuration,
                    } => {
                        if let Some(term) = self.storage.term_at(through).await? {
                            self.storage
                                .commit_batch(WriteBatch {
                                    compact_to: Some((through, term)),
                                    log_start_config: configuration,
                                    ..Default::default()
                                })
                                .await?;
                            core.compacted(through);
                        }
                    }
                    Action::Answer(answer) => self.answer(answer),
                    Action::Changed { role: now, .. } => role.store(now.as_u8(), Ordering::Relaxed),
                }
            }
        }
    }

    fn answer(&mut self, answer: Answer) {
        match answer {
            Answer::Propose { token, result } => {
                if let Some(reply) = self.replies.proposals.remove(&token) {
                    let _ = reply.send(result);
                }
            }
            Answer::ReadIndex { token, result } => {
                if let Some(reply) = self.replies.reads.remove(&token) {
                    let _ = reply.send(result);
                }
            }
            Answer::ChangeMembership { token, result } => {
                if let Some(reply) = self.replies.changes.remove(&token) {
                    let _ = reply.send(result);
                }
            }
        }
    }

    // ── Snapshots: sending ─────────────────────────────────

    async fn start_snapshot(
        &mut self,
        core: &Core<N>,
        to: N,
        index: u64,
        term: u64,
        configuration: Option<SnapshotConfiguration<N>>,
    ) -> Result<(), S::Error> {
        let resumes = self
            .outgoing
            .get(&to)
            .is_some_and(|outgoing| outgoing.index == index && outgoing.term == term);
        if !resumes {
            let data = Arc::new(self.storage.read_state().await?);
            self.outgoing.insert(
                to,
                Outgoing {
                    index,
                    term,
                    configuration,
                    data,
                    offset: 0,
                    sent_at: 0,
                },
            );
        }
        self.send_chunk(core, to);
        Ok(())
    }

    fn send_chunk(&mut self, core: &Core<N>, to: N) {
        let now = self.now;
        let me = self.me;
        let term = core.status().current_term;
        let chunk_bytes = self.chunk_bytes.max(1);
        let Some(outgoing) = self.outgoing.get_mut(&to) else {
            return;
        };
        outgoing.sent_at = now;
        let start = (outgoing.offset as usize).min(outgoing.data.len());
        let end = (start + chunk_bytes).min(outgoing.data.len());
        let done = end >= outgoing.data.len();
        let (members, joint_old, active_config_index) = match (&outgoing.configuration, done) {
            (Some(configuration), true) => (
                configuration.members.clone(),
                configuration.joint_old.clone(),
                Some(configuration.index),
            ),
            _ => (Vec::new(), None, None),
        };
        let chunk = InstallSnapshotReq {
            leader: me,
            term,
            last_included_index: outgoing.index,
            last_included_term: outgoing.term,
            offset: start as u64,
            done,
            data: outgoing.data[start..end].to_vec(),
            members,
            joint_old,
            active_config_index,
        };
        self.send(to, Envelope::SnapshotChunk(chunk));
    }

    fn on_snapshot_ack(&mut self, core: &Core<N>, from: N, ack: InstallSnapshotResp) {
        let Some(outgoing) = self.outgoing.get_mut(&from) else {
            return;
        };
        if outgoing.index != ack.last_included_index || outgoing.term != ack.last_included_term {
            return;
        }
        let total = outgoing.data.len() as u64;
        // The receiver is authoritative: after a restart it holds nothing,
        // and the stream rewinds.
        outgoing.offset = ack.bytes_received.min(total);
        if ack.bytes_received >= total {
            self.outgoing.remove(&from);
        } else {
            self.send_chunk(core, from);
        }
    }

    /// Resend chunks whose acknowledgement is overdue.
    fn resend_chunks(&mut self, core: &Core<N>) {
        let overdue: Vec<N> = self
            .outgoing
            .iter()
            .filter(|(_, outgoing)| outgoing.sent_at + self.resend_ms <= self.now)
            .map(|(&peer, _)| peer)
            .collect();
        for peer in overdue {
            self.send_chunk(core, peer);
        }
    }

    fn next_resend(&self) -> Option<u64> {
        self.outgoing
            .values()
            .map(|outgoing| outgoing.sent_at + self.resend_ms)
            .min()
    }

    // ── Snapshots: receiving ───────────────────────────────

    async fn on_chunk(
        &mut self,
        core: &mut Core<N>,
        from: N,
        chunk: InstallSnapshotReq<N>,
    ) -> Result<(), S::Error> {
        let status = core.status();
        let ack = |bytes_received: u64| InstallSnapshotResp {
            term: status.current_term,
            last_included_index: chunk.last_included_index,
            last_included_term: chunk.last_included_term,
            bytes_received,
        };
        // Only the leader this replica follows at its term may install a
        // snapshot; the core learns of terms and leaders from its messages.
        if chunk.leader != from
            || chunk.term != status.current_term
            || status.leader_hint != Some(from)
            || status.role != Role::Follower
        {
            self.send(from, Envelope::SnapshotAck(ack(0)));
            return Ok(());
        }
        if chunk.last_included_index <= status.snap_last_index
            || chunk.last_included_index <= status.commit_index
        {
            // Covered already, by a snapshot or by committed entries.
            self.incoming = None;
            let held = chunk.offset + chunk.data.len() as u64;
            self.send(from, Envelope::SnapshotAck(ack(held)));
            return Ok(());
        }
        let same = self.incoming.as_ref().is_some_and(|incoming| {
            incoming.leader == from
                && incoming.term == chunk.term
                && incoming.index == chunk.last_included_index
                && incoming.index_term == chunk.last_included_term
        });
        if !same {
            self.incoming = Some(Incoming {
                leader: from,
                term: chunk.term,
                index: chunk.last_included_index,
                index_term: chunk.last_included_term,
                buffer: Vec::new(),
            });
        }
        let incoming = self.incoming.as_mut().expect("set above");
        let held = incoming.buffer.len() as u64;
        if chunk.offset > held {
            self.send(from, Envelope::SnapshotAck(ack(held)));
            return Ok(());
        }
        if chunk.offset == held {
            if incoming.buffer.len().saturating_add(chunk.data.len()) > self.max_snapshot_bytes {
                self.incoming = None;
                self.send(from, Envelope::SnapshotAck(ack(0)));
                return Ok(());
            }
            incoming.buffer.extend_from_slice(&chunk.data);
        }
        let held = incoming.buffer.len() as u64;
        if !chunk.done {
            self.send(from, Envelope::SnapshotAck(ack(held)));
            return Ok(());
        }
        // Membership and its provenance are one claim; an incomplete or
        // future one is refused before anything is installed.
        let configuration = match (chunk.members.is_empty(), chunk.active_config_index) {
            (false, Some(index)) if index <= chunk.last_included_index => {
                Some(SnapshotConfiguration {
                    members: chunk.members.clone(),
                    joint_old: chunk.joint_old.clone(),
                    index,
                })
            }
            (true, None) if chunk.joint_old.is_none() => None,
            _ => {
                self.incoming = None;
                self.send(from, Envelope::SnapshotAck(ack(0)));
                return Ok(());
            }
        };
        let incoming = self.incoming.take().expect("set above");
        // One switch: the state, the snapshot boundary, and the log suffix
        // kept only if it continues the snapshot.
        let switch =
            core.snapshot_switch(incoming.index, incoming.index_term, configuration.as_ref());
        self.storage
            .commit_batch(WriteBatch {
                truncate_after: switch.truncate_after,
                compact_to: Some((incoming.index, incoming.index_term)),
                appends: Vec::new(),
                state: Some(incoming.buffer),
                meta: Some(switch.meta),
                active_config: Some(switch.active_config),
                log_start_config: switch.log_start_config,
            })
            .await?;
        core.snapshot_installed(incoming.index, incoming.index_term, configuration);
        self.send(from, Envelope::SnapshotAck(ack(held)));
        Ok(())
    }

    async fn on_envelope(
        &mut self,
        core: &mut Core<N>,
        from: N,
        envelope: Envelope<N>,
    ) -> Result<(), S::Error> {
        match envelope {
            Envelope::Raft(message) => core.receive(from, message),
            Envelope::SnapshotChunk(chunk) => self.on_chunk(core, from, chunk).await?,
            Envelope::SnapshotAck(ack) => self.on_snapshot_ack(core, from, ack),
        }
        Ok(())
    }
}

/// The most inbox messages one round hands the core before carrying out
/// its actions.
const MAX_MESSAGES_PER_ROUND: usize = 1024;

/// Run a worker to completion: `Ok` on shutdown, `Err` when its store
/// fails, at boot or later.
#[allow(clippy::too_many_arguments)]
pub async fn run_worker<N, S, T, C, R, A, F>(
    storage: S,
    transport: Arc<T>,
    cfg: Config<N>,
    inbox_rx: fmpsc::UnboundedReceiver<RaftMsg<N>>,
    apply_sink: A,
    clock: C,
    rng: R,
    role_atomic: Arc<AtomicU8>,
    init_done: F,
) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
    F: FnOnce(bool),
{
    run_worker_with_status(
        storage,
        transport,
        cfg,
        inbox_rx,
        apply_sink,
        clock,
        rng,
        role_atomic,
        Arc::new(std::sync::RwLock::new(None)),
        init_done,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn run_worker_with_status<N, S, T, C, R, A, F>(
    storage: S,
    transport: Arc<T>,
    cfg: Config<N>,
    mut inbox_rx: fmpsc::UnboundedReceiver<RaftMsg<N>>,
    apply_sink: A,
    clock: C,
    mut rng: R,
    role_atomic: Arc<AtomicU8>,
    status: SharedWorkerStatus<N>,
    init_done: F,
) -> Result<(), S::Error>
where
    N: NodeId,
    S: Storage<N>,
    T: Transport<N>,
    C: Clock,
    R: Rng,
    A: ApplySink,
    F: FnOnce(bool),
{
    let recovered = match recover(&storage).await {
        Ok(recovered) => {
            init_done(true);
            recovered
        }
        Err(error) => {
            init_done(false);
            return Err(error);
        }
    };
    let status_valid_for = Duration::from_millis(
        cfg.election_timeout_ms
            .1
            .max(cfg.heartbeat_interval_ms.saturating_mul(3))
            .max(1),
    );
    let start = clock.now();
    let mut driver = Driver {
        me: cfg.me,
        storage,
        transport,
        apply_sink,
        replies: Replies {
            next: 0,
            proposals: BTreeMap::new(),
            reads: BTreeMap::new(),
            changes: BTreeMap::new(),
            _node: core::marker::PhantomData,
        },
        outgoing: BTreeMap::new(),
        incoming: None,
        status_replies: Vec::new(),
        chunk_bytes: cfg.install_snapshot_chunk_bytes,
        max_snapshot_bytes: cfg.max_snapshot_bytes,
        resend_ms: cfg.resend_timeout_ms,
        now: 0,
    };
    let mut core = Core::new(cfg, recovered, 0, rng.next_u64());
    let publish = |core: &Core<N>| {
        if let Ok(mut published) = status.write() {
            *published = Some(PublishedWorkerStatus {
                snapshot: core.status().into(),
                valid_until: std::time::Instant::now() + status_valid_for,
            });
        }
    };
    let result = async {
        driver.run_actions(&mut core, &role_atomic).await?;
        publish(&core);
        loop {
            let wake = driver.next_resend().map_or(core.next_deadline(), |resend| {
                resend.min(core.next_deadline())
            });
            let timer = clock
                .sleep_until(clock.add(start, Duration::from_millis(wake)))
                .fuse();
            futures_util::pin_mut!(timer);
            let next = inbox_rx.next().fuse();
            futures_util::pin_mut!(next);
            let mut message = futures_util::select! {
                message = next => match message {
                    Some(RaftMsg::Shutdown) | None => break,
                    Some(message) => Some(message),
                },
                _ = timer => None,
            };
            let now = clock.millis_since(start, clock.now());
            driver.now = now;
            core.tick(now);
            // Everything already queued joins this round, so the core
            // coalesces it into one write.
            let mut stop = false;
            let mut handled = 0;
            while let Some(next) = message.take() {
                if matches!(next, RaftMsg::Shutdown) {
                    stop = true;
                    break;
                }
                let from = match &next {
                    RaftMsg::Deliver { from, .. } => Some(*from),
                    _ => None,
                };
                if let Some(envelope) = driver.handle(&mut core, next)
                    && let Some(from) = from
                {
                    if matches!(envelope, Envelope::SnapshotChunk(_)) {
                        // A snapshot switch follows every write before it.
                        driver.run_actions(&mut core, &role_atomic).await?;
                    }
                    driver.on_envelope(&mut core, from, envelope).await?;
                }
                handled += 1;
                if handled < MAX_MESSAGES_PER_ROUND {
                    message = match inbox_rx.try_recv() {
                        Ok(next) => Some(next),
                        Err(fmpsc::TryRecvError::Closed) => {
                            stop = true;
                            None
                        }
                        Err(fmpsc::TryRecvError::Empty) => None,
                    };
                }
            }
            driver.resend_chunks(&core);
            driver.run_actions(&mut core, &role_atomic).await?;
            publish(&core);
            for reply in driver.status_replies.drain(..) {
                let _ = reply.send(core.status().into());
            }
            if stop {
                break;
            }
        }
        Ok(())
    }
    .await;
    // Before the pending replies and the inbox drop: a caller who sees the
    // worker gone sees it lead nothing.
    if let Ok(mut published) = status.write() {
        *published = None;
    }
    role_atomic.store(Role::Follower.as_u8(), Ordering::Relaxed);
    result
}

/// What the core needs from the store at boot.
async fn recover<N: NodeId, S: Storage<N>>(storage: &S) -> Result<Recovered<N>, S::Error> {
    let meta = storage.load_meta().await?;
    let last = storage.last_index();
    let entries = if last > meta.snap_last_index {
        storage.entries(meta.snap_last_index + 1, last).await?
    } else {
        Vec::new()
    };
    let active_config = storage.active_config().await?;
    let log_start_config = storage.log_start_config().await?;
    let applied = storage.applied_index().await?.unwrap_or(meta.commit_index);
    Ok(Recovered {
        meta,
        entries,
        active_config,
        log_start_config,
        applied,
        vote_floor: None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::{StdClock, StdRng};
    use crate::log_entry::LogEntry;
    use crate::message::{AppendResult, Message};
    use crate::storage::MemStorage;
    use crate::testutil::block_on;

    /// Records what the worker sends, for each recipient.
    #[derive(Default)]
    struct Recording {
        sent: std::sync::Mutex<Vec<(u16, Envelope<u16>)>>,
    }

    impl Transport<u16> for Recording {
        fn send(&self, _from: u16, to: u16, envelope: Envelope<u16>) {
            self.sent.lock().unwrap().push((to, envelope));
        }
    }

    impl Recording {
        fn take(&self, to: u16) -> Vec<Envelope<u16>> {
            let mut sent = self.sent.lock().unwrap();
            let (theirs, rest) = sent.drain(..).partition(|(at, _)| *at == to);
            *sent = rest;
            theirs.into_iter().map(|(_, envelope)| envelope).collect()
        }
    }

    fn cfg(me: u16, members: Vec<u16>) -> Config<u16> {
        let mut c = Config::new(me, members, [0u8; 32]);
        c.election_timeout_ms = (5_000, 10_000);
        c.heartbeat_interval_ms = 500;
        c
    }

    fn spawn(storage: MemStorage<u16>, cfg: Config<u16>) -> (Worker<u16>, Arc<Recording>) {
        let transport = Arc::new(Recording::default());
        let worker = Worker::spawn_with(
            storage,
            transport.clone(),
            cfg,
            (),
            StdClock,
            StdRng::from_entropy(),
        );
        (worker, transport)
    }

    /// Deliver `envelope` from `from` and return what the worker sent back
    /// once it has handled it (and made its writes durable).
    fn ask(
        handle: &WorkerHandle<u16>,
        transport: &Recording,
        from: u16,
        envelope: Envelope<u16>,
    ) -> Vec<Envelope<u16>> {
        handle.deliver(from, envelope);
        block_on(handle.snapshot()).expect("worker alive");
        transport.take(from)
    }

    fn append(
        term: u64,
        leader: u16,
        prev: (u64, u64),
        entries: Vec<LogEntry<u16>>,
    ) -> Envelope<u16> {
        Envelope::Raft(Message::Append {
            term,
            leader,
            prev_index: prev.0,
            prev_term: prev.1,
            commit: 0,
            round: 1,
            entries,
        })
    }

    fn vote(term: u64, candidate: u16, last: (u64, u64)) -> Envelope<u16> {
        Envelope::Raft(Message::Vote {
            term,
            candidate,
            last_index: last.0,
            last_term: last.1,
        })
    }

    fn granted(answers: &[Envelope<u16>]) -> Option<(u64, bool)> {
        answers.iter().find_map(|envelope| match envelope {
            Envelope::Raft(Message::VoteAnswer { term, granted }) => Some((*term, *granted)),
            _ => None,
        })
    }

    fn matched(answers: &[Envelope<u16>]) -> Option<u64> {
        answers
            .iter()
            .filter_map(|envelope| match envelope {
                Envelope::Raft(Message::AppendAnswer {
                    result: AppendResult::Matched { matched },
                    ..
                }) => Some(*matched),
                _ => None,
            })
            .max()
    }

    #[test]
    fn worker_starts_in_follower_role() {
        let (worker, _) = spawn(
            MemStorage::new(),
            cfg(0xAAAA, alloc::vec![0xAAAA, 0xBBBB, 0xCCCC]),
        );
        let snap = block_on(worker.handler().snapshot()).expect("worker alive");
        assert_eq!(snap.role, Role::Follower);
        assert_eq!(snap.current_term, 0);
        assert_eq!(snap.voted_for, None);
        assert_eq!(snap.last_log_index, 0);
        worker.shutdown();
    }

    #[test]
    fn cached_snapshot_expires_when_the_worker_stops_publishing() {
        let (tx, _rx) = fmpsc::unbounded();
        let snapshot = WorkerSnapshot {
            role: Role::Follower,
            current_term: 7,
            voted_for: None,
            last_log_index: 11,
            commit_index: 11,
            snap_last_index: 0,
            durable_index: 11,
            members: alloc::vec![0xAAAA, 0xBBBB],
            joint_old: None,
            active_config_index: Some(11),
            retirement_final_index: None,
            leader_hint: Some(0xAAAA),
        };
        let handle = WorkerHandle {
            inbox: Inbox { inner: tx },
            role: Arc::new(AtomicU8::new(Role::Follower.as_u8())),
            status: Arc::new(std::sync::RwLock::new(Some(PublishedWorkerStatus {
                snapshot,
                valid_until: std::time::Instant::now()
                    .checked_sub(Duration::from_millis(1))
                    .unwrap(),
            }))),
        };
        assert!(
            handle.cached_snapshot().is_none(),
            "an observation older than its worker lease cannot route clients"
        );
    }

    fn lead_alone(handle: &WorkerHandle<u16>) {
        let until = std::time::Instant::now() + Duration::from_millis(1_000);
        while block_on(handle.snapshot()).is_none_or(|snap| snap.role != Role::Leader) {
            assert!(std::time::Instant::now() < until, "no leadership");
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    #[test]
    fn solo_cluster_self_elects_and_proposes() {
        let mut cfg = cfg(0xAAAA, alloc::vec![0xAAAA]);
        cfg.election_timeout_ms = (10, 30);
        let (worker, _) = spawn(MemStorage::new(), cfg);
        let h = worker.handler();
        lead_alone(&h);
        // Index 1 is the leader's no-op.
        let index = block_on(h.propose(alloc::vec![1, 2, 3])).expect("propose");
        assert_eq!(index, 2);
        let snap = block_on(h.snapshot()).unwrap();
        assert_eq!(snap.role, Role::Leader);
        assert_eq!(snap.last_log_index, 2);
        assert_eq!(snap.commit_index, 2);
        worker.shutdown();
    }

    #[test]
    fn compaction_never_crosses_durable_application_cursor() {
        // The state reflects index 1 only: the no-op may be compacted, the
        // unapplied entry 2 may not.
        let mut cfg = cfg(0xAAAA, alloc::vec![0xAAAA]);
        cfg.election_timeout_ms = (10, 30);
        cfg.heartbeat_interval_ms = 5;
        cfg.compact_hysteresis = 1;
        let (worker, _) = spawn(MemStorage::new().with_applied_index(1), cfg);
        let h = worker.handler();
        lead_alone(&h);
        assert_eq!(block_on(h.propose(alloc::vec![9])).unwrap(), 2);
        std::thread::sleep(Duration::from_millis(30));
        let snap = block_on(h.snapshot()).unwrap();
        assert_eq!(snap.commit_index, 2);
        assert_eq!(snap.snap_last_index, 1);
        assert_eq!(snap.last_log_index, 2);
        worker.shutdown();
    }

    #[test]
    fn follower_accepts_heartbeat_and_advances_term() {
        let (worker, transport) = spawn(
            MemStorage::new(),
            cfg(0xAAAA, alloc::vec![0xAAAA, 0xBBBB, 0xCCCC]),
        );
        let h = worker.handler();
        let answers = ask(
            &h,
            &transport,
            0xBBBB,
            append(5, 0xBBBB, (0, 0), alloc::vec![]),
        );
        assert!(answers.iter().any(|envelope| matches!(
            envelope,
            Envelope::Raft(Message::AppendAnswer {
                term: 5,
                result: AppendResult::Matched { .. },
                ..
            })
        )));
        assert_eq!(block_on(h.snapshot()).unwrap().current_term, 5);
        worker.shutdown();
    }

    #[test]
    fn idle_worker_does_not_spin() {
        use core::sync::atomic::{AtomicU64, Ordering as AO};

        #[derive(Clone)]
        struct CountingClock {
            sleep_calls: Arc<AtomicU64>,
        }
        impl Clock for CountingClock {
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
            fn millis_since(&self, earlier: Self::Instant, later: Self::Instant) -> u64 {
                StdClock.millis_since(earlier, later)
            }
        }

        let mut cfg_idle = Config::new(0xAAAA, alloc::vec![0xAAAA, 0xBBBB, 0xCCCC], [0u8; 32]);
        cfg_idle.election_timeout_ms = (10_000, 10_000);
        cfg_idle.heartbeat_interval_ms = 1_000;
        let sleep_calls = Arc::new(AtomicU64::new(0));
        let worker = Worker::spawn_with(
            MemStorage::<u16>::new(),
            Arc::new(Recording::default()),
            cfg_idle,
            (),
            CountingClock {
                sleep_calls: sleep_calls.clone(),
            },
            StdRng::from_entropy(),
        );
        std::thread::sleep(Duration::from_millis(100));
        let n = sleep_calls.load(AO::Relaxed);
        worker.shutdown();
        // Single digits when parked; thousands in a spin.
        assert!(n < 100, "idle worker looped {n} times in 100ms");
    }

    #[test]
    fn follower_truncates_multiple_entries_at_root_conflict() {
        let (worker, transport) = spawn(
            MemStorage::new(),
            cfg(0xAAAA, alloc::vec![0xAAAA, 0xBBBB, 0xCCCC]),
        );
        let h = worker.handler();
        let entries = |term: u64| {
            (1..=3)
                .map(|index| LogEntry::data(index, term, alloc::vec![term as u8]))
                .collect()
        };
        let first = ask(
            &h,
            &transport,
            0xBBBB,
            append(1, 0xBBBB, (0, 0), entries(1)),
        );
        assert_eq!(matched(&first), Some(3));
        // A later leader replaces all three from the first.
        let second = ask(
            &h,
            &transport,
            0xCCCC,
            append(2, 0xCCCC, (0, 0), entries(2)),
        );
        assert_eq!(matched(&second), Some(3));
        let snap = block_on(h.snapshot()).unwrap();
        assert_eq!(snap.last_log_index, 3);
        assert_eq!(snap.current_term, 2);
        worker.shutdown();
    }

    fn chunk(term: u64, index: u64, index_term: u64, data: Vec<u8>) -> Envelope<u16> {
        Envelope::SnapshotChunk(InstallSnapshotReq {
            leader: 0xBBBB,
            term,
            last_included_index: index,
            last_included_term: index_term,
            offset: 0,
            done: true,
            data,
            members: Vec::new(),
            joint_old: None,
            active_config_index: None,
        })
    }

    fn acked(answers: &[Envelope<u16>]) -> Option<u64> {
        answers.iter().find_map(|envelope| match envelope {
            Envelope::SnapshotAck(ack) => Some(ack.bytes_received),
            _ => None,
        })
    }

    #[test]
    fn snapshot_install_past_last_log_index() {
        let (worker, transport) = spawn(
            MemStorage::new(),
            cfg(0xAAAA, alloc::vec![0xAAAA, 0xBBBB, 0xCCCC]),
        );
        let h = worker.handler();
        // The leader's heartbeat establishes term 5 and the leader first.
        ask(
            &h,
            &transport,
            0xBBBB,
            append(5, 0xBBBB, (100, 4), alloc::vec![]),
        );
        let answers = ask(
            &h,
            &transport,
            0xBBBB,
            chunk(5, 100, 4, alloc::vec![0xAA; 32]),
        );
        assert_eq!(acked(&answers), Some(32));
        assert_eq!(
            matched(&answers),
            Some(100),
            "the core acknowledges the snapshot"
        );
        let snap = block_on(h.snapshot()).unwrap();
        assert_eq!(snap.snap_last_index, 100);
        assert_eq!(snap.commit_index, 100);
        assert_eq!(snap.last_log_index, 100);
        worker.shutdown();
    }

    #[test]
    fn vote_refused_when_candidate_log_is_stale() {
        let (worker, transport) = spawn(
            MemStorage::new(),
            cfg(0xAAAA, alloc::vec![0xAAAA, 0xBBBB, 0xCCCC]),
        );
        let h = worker.handler();
        ask(
            &h,
            &transport,
            0xBBBB,
            append(
                5,
                0xBBBB,
                (0, 0),
                alloc::vec![LogEntry::data(1, 5, alloc::vec![1])],
            ),
        );
        // A higher index cannot make up for a lower last term.
        let answers = ask(&h, &transport, 0xCCCC, vote(6, 0xCCCC, (99, 2)));
        assert_eq!(granted(&answers), Some((6, false)));
        // Nor the same last term with a shorter log.
        let answers = ask(&h, &transport, 0xCCCC, vote(7, 0xCCCC, (0, 5)));
        assert_eq!(granted(&answers), Some((7, false)));
        worker.shutdown();
    }

    #[test]
    fn at_most_one_vote_per_term_handles_same_candidate_twice() {
        let (worker, transport) = spawn(
            MemStorage::new(),
            cfg(0xAAAA, alloc::vec![0xAAAA, 0xBBBB, 0xCCCC]),
        );
        let h = worker.handler();
        assert_eq!(
            granted(&ask(&h, &transport, 0xBBBB, vote(4, 0xBBBB, (0, 0)))),
            Some((4, true))
        );
        // The same candidate again: the same answer, the same vote.
        assert_eq!(
            granted(&ask(&h, &transport, 0xBBBB, vote(4, 0xBBBB, (0, 0)))),
            Some((4, true))
        );
        let snap = block_on(h.snapshot()).unwrap();
        assert_eq!((snap.voted_for, snap.current_term), (Some(0xBBBB), 4));
        // Another candidate at the same term is refused.
        assert_eq!(
            granted(&ask(&h, &transport, 0xCCCC, vote(4, 0xCCCC, (0, 0)))),
            Some((4, false))
        );
        assert_eq!(block_on(h.snapshot()).unwrap().voted_for, Some(0xBBBB));
        worker.shutdown();
    }

    #[test]
    fn install_snapshot_is_idempotent_on_duplicate_delivery() {
        let (worker, transport) = spawn(
            MemStorage::new(),
            cfg(0xAAAA, alloc::vec![0xAAAA, 0xBBBB, 0xCCCC]),
        );
        let h = worker.handler();
        ask(
            &h,
            &transport,
            0xBBBB,
            append(7, 0xBBBB, (50, 6), alloc::vec![]),
        );
        assert_eq!(
            acked(&ask(
                &h,
                &transport,
                0xBBBB,
                chunk(7, 50, 6, alloc::vec![0xAA; 16])
            )),
            Some(16)
        );
        let snap = block_on(h.snapshot()).unwrap();
        assert_eq!(
            (snap.snap_last_index, snap.commit_index, snap.current_term),
            (50, 50, 7)
        );
        // A duplicate changes nothing, and is acknowledged as held.
        assert_eq!(
            acked(&ask(
                &h,
                &transport,
                0xBBBB,
                chunk(7, 50, 6, alloc::vec![0xAA; 16])
            )),
            Some(16)
        );
        let snap = block_on(h.snapshot()).unwrap();
        assert_eq!((snap.snap_last_index, snap.commit_index), (50, 50));
        // An older snapshot does not move the boundary back.
        ask(
            &h,
            &transport,
            0xBBBB,
            chunk(7, 30, 5, alloc::vec![0xBB; 8]),
        );
        assert_eq!(block_on(h.snapshot()).unwrap().snap_last_index, 50);
        worker.shutdown();
    }
}
