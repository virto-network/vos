//! An agent's replica group on this node: its consensus core, driven by
//! the node's log writer and the network, and its applier, which applies
//! the committed log in order, the same way on every replica.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vos_net::Class;
use vos_raft::core::{
    Action, Answer, ChangeMembershipError, Core, ProposeError, ReadIndexError,
    SnapshotConfiguration, Write,
};
use vos_raft::{Config as RaftConfig, Message, Role};
use vos_wire::ids::AgentId;
use vos_wire::peer::{
    Configuration, CreationRecord, Manifest, NodeNumber, PeerMessage, Placement, SnapshotAck,
    SnapshotChunk,
};
use vos_wire::records::{Installed, unstored};
use vos_wire::result::{WorkResult, Write as StateWrite};
use vos_wire::{Decode, Encode, keys};

use crate::node::{Inner, ran};
use crate::pvm::{self, Fault};
use crate::raft::{self, EntryReports};
use crate::storage::Change;
use crate::store::{EntryKind, Export, FjallSnapshot, LogEntry, Store, View, next_epoch};

/// How long a group waits for blobs it asked for before asking again,
/// another member.
const BLOB_RETRY: Duration = Duration::from_secs(1);
/// The first wait before retrying an apply the node failed, doubled each
/// time up to [`MAX_BACKOFF`].
const BACKOFF: Duration = Duration::from_millis(50);
const MAX_BACKOFF: Duration = Duration::from_secs(5);
/// Inputs a driver takes in one round, so the core joins them in one
/// write.
const ROUND: usize = 1024;
/// Snapshot chunks a stream sends past its follower's acknowledgement.
const CHUNKS_AHEAD: u64 = 4;
/// How long a stream waits for an acknowledgement that moves before it
/// sends its chunks again, and before it gives up.
const CHUNK_RESEND: Duration = Duration::from_secs(2);
const STREAM_SILENCE: Duration = Duration::from_secs(10);
/// How long a stream whose chunks are all staged holds compaction, and
/// keeps the core from starting another, waiting for its follower to
/// switch.
const STREAM_HOLD: Duration = Duration::from_secs(60);
/// How long a follower keeps a snapshot it stages without a new chunk.
const INSTALL_IDLE: Duration = Duration::from_secs(30);
/// Rows of an old epoch one write removes.
const DROP_ROWS: usize = 4096;

/// Where a proposal's answer goes: the index it took, or why not, and
/// when the driver answered.
pub(crate) type Proposed = smol::channel::Sender<(Result<u64, ProposeError>, Instant)>;

/// What a group hears from the network and the node: bounded, and
/// dropped when full.
pub(crate) enum Input {
    /// A Raft message from a peer, already checked.
    Raft {
        from: NodeNumber,
        message: Message<NodeNumber>,
    },
    /// Blobs arrived that the group's entries, or a snapshot it installs,
    /// may wait for.
    Blobs,
    /// A snapshot chunk from the leader this replica follows, `from`.
    Chunk {
        from: NodeNumber,
        chunk: SnapshotChunk,
    },
    /// A follower's acknowledgement of a snapshot stream.
    ChunkAck { from: NodeNumber, ack: SnapshotAck },
}

/// What a group hears from its own leader loop, never dropped.
pub(crate) enum Local {
    /// A work result to replicate in `term`: its index, or why not.
    Propose {
        term: u64,
        payload: Vec<u8>,
        answer: Proposed,
    },
    /// This replica's leader loop stopped for good: it hands leadership
    /// over and never campaigns again, but goes on applying.
    Retire,
    /// A read index: an index to apply through before reading, once a
    /// quorum has confirmed this replica still leads.
    ReadIndex {
        answer: smol::channel::Sender<Result<u64, ReadIndexError>>,
    },
    /// Replace the group's members, `current` as the caller saw them, by
    /// `members`: answered with the index of the joint configuration,
    /// which the core finalizes once it commits; refused as in progress
    /// when the core's configuration is not `current`.
    ChangeMembership {
        current: Vec<NodeNumber>,
        members: Vec<NodeNumber>,
        answer: smol::channel::Sender<Result<u64, ChangeMembershipError>>,
    },
    /// `node` came back, by the pair heartbeat: a leader sends it a
    /// heartbeat at once ([`vos_raft::core::Core::probe`]).
    Probe(NodeNumber),
    /// Something changed that the group's next round should see, such as
    /// the writer's health.
    Wake,
    /// The placement of `order` reached the directory, `kept` or not.
    Placed { order: (u64, u64, bool), kept: bool },
    /// The snapshot stream to `to`, named by `term` and `index`, ended:
    /// `done` once its follower staged every chunk.
    StreamEnded {
        to: NodeNumber,
        term: u64,
        index: u64,
        done: bool,
    },
}

/// How long a read index may wait for a quorum to confirm the leader.
const READ_INDEX_MS: u64 = 2_000;

/// How many results' outcomes a group remembers, for its leader loop to
/// read after its own apply.
const OUTCOMES: usize = 256;

/// A group's state, as its driver, its applier, its leader loop and
/// ingress share it.
#[derive(Clone, Copy, Debug)]
pub(crate) struct State {
    pub role: Role,
    pub term: u64,
    pub leader: Option<NodeNumber>,
    /// The first index of the term this replica leads, while it leads.
    pub leading_from: Option<u64>,
    pub commit: u64,
    /// The highest index this replica holds durably, blobs included.
    pub written: u64,
    pub applied: u64,
    /// The commit index the replica recovered: queries wait until it is
    /// applied.
    pub recovered: u64,
    /// When the commit index last moved: a stage's end as the driver saw
    /// it, not as a waiter woken later does.
    pub commit_at: Option<Instant>,
    /// When the applied index last moved, as the applier saw it.
    pub applied_at: Option<Instant>,
    pub stopped: bool,
    /// The replica has held a committed configuration naming it.
    pub established: bool,
}

pub(crate) struct Shared {
    pub agent: AgentId,
    pub record: CreationRecord,
    /// The members its core starts with, when its store holds none.
    pub members: Vec<NodeNumber>,
    /// The agent's identity: its record's hash, which clients sign for.
    pub identity: [u8; 32],
    state: Mutex<State>,
    changed: event_listener::Event,
    /// Whether each recent work result took: accumulate advanced the
    /// agent's version with it, rather than skipping it or failing.
    outcomes: Mutex<VecDeque<(u64, bool)>>,
    /// Held by the applier while it applies an entry, and by a snapshot
    /// switch: an apply never lands on the state a switch replaced.
    pub applying: smol::lock::Mutex<()>,
    /// When the group's driver last went round, on the node's liveness
    /// clock: a leader whose driver stopped going round is not vouched
    /// for.
    pub woke: std::sync::atomic::AtomicU64,
}

impl Shared {
    pub fn new(record: CreationRecord, members: Vec<NodeNumber>) -> Self {
        Self {
            agent: record.agent,
            identity: crate::identity(&record),
            record,
            members,
            state: Mutex::new(State {
                role: Role::Follower,
                term: 0,
                leader: None,
                leading_from: None,
                commit: 0,
                written: 0,
                applied: 0,
                recovered: 0,
                commit_at: None,
                applied_at: None,
                stopped: false,
                established: false,
            }),
            changed: event_listener::Event::new(),
            outcomes: Mutex::new(VecDeque::new()),
            applying: smol::lock::Mutex::new(()),
            woke: std::sync::atomic::AtomicU64::new(0),
        }
    }

    /// Whether the work result at `index` took, if it was applied lately.
    pub fn outcome(&self, index: u64) -> Option<bool> {
        self.outcomes
            .lock()
            .expect("the outcomes")
            .iter()
            .find(|(at, _)| *at == index)
            .map(|(_, took)| *took)
    }

    fn record_outcome(&self, index: u64, took: bool) {
        let mut outcomes = self.outcomes.lock().expect("the outcomes");
        if outcomes.len() == OUTCOMES {
            outcomes.pop_front();
        }
        outcomes.push_back((index, took));
    }

    pub fn state(&self) -> State {
        *self.state.lock().expect("the group's state")
    }

    pub fn update(&self, change: impl FnOnce(&mut State)) {
        change(&mut self.state.lock().expect("the group's state"));
        self.changed.notify(usize::MAX);
    }

    /// The state once `until` holds of it.
    pub async fn wait(&self, until: impl Fn(&State) -> bool) -> State {
        loop {
            let changed = self.changed.listen();
            let state = self.state();
            if until(&state) {
                return state;
            }
            changed.await;
        }
    }

    pub fn stop(&self) {
        self.update(|state| state.stopped = true);
    }
}

/// Drive `shared`'s group until it stops, its inboxes close, or storage
/// fails.
pub(crate) async fn drive(
    inner: Arc<Inner>,
    shared: Arc<Shared>,
    inbox: smol::channel::Receiver<Input>,
    local: smol::channel::Receiver<Local>,
) {
    match Driver::start(Arc::clone(&inner), Arc::clone(&shared)).await {
        Ok(driver) => driver.run(inbox, local).await,
        Err(error) => {
            tracing::error!(
                agent = shared.agent.0,
                "the group cannot start: {error}; it stops"
            );
            shared.stop();
        }
    }
}

struct Driver {
    inner: Arc<Inner>,
    shared: Arc<Shared>,
    agent: AgentId,
    core: Core<NodeNumber>,
    start: Instant,
    reports: EntryReports,
    /// Each write not yet reported with its blobs, by sequence, with the
    /// log's last index after it.
    writes: VecDeque<(u64, u64)>,
    /// The log's last index as written to the store. [`State::written`]
    /// reaches it only once the entries' blobs are stored too.
    last_index: u64,
    proposals: HashMap<u64, Proposed>,
    reads: HashMap<u64, smol::channel::Sender<Result<u64, ReadIndexError>>>,
    next_token: u64,
    /// The blobs asked for last, and when.
    asked: Option<(Instant, Vec<[u8; 32]>)>,
    /// Which member to ask next.
    turn: usize,
    /// The leader loop stopped for good.
    retired: bool,
    /// The writer health last reported to the core.
    stalled: bool,
    /// The snapshot streams this replica runs as leader, by follower.
    streams: HashMap<NodeNumber, Stream>,
    /// The snapshot this replica stages, from the leader it follows.
    install: Option<Install>,
    /// The programs a staged snapshot waits for before its switch.
    install_missing: Vec<[u8; 32]>,
    /// Snapshot chunks taken this round, staged once it is processed.
    chunks: VecDeque<(NodeNumber, SnapshotChunk)>,
    /// The highest compaction bound the core gave.
    compact_bound: u64,
    /// A compaction is due at the next chance.
    compact_due: bool,
    memberships: HashMap<u64, smol::channel::Sender<Result<u64, ChangeMembershipError>>>,
    /// The order of the placement this replica last announced as leader.
    announced: Option<(u64, u64, bool)>,
    /// A placement on its way to the directory: kept off the driver, which
    /// never waits on the node-wide lock a placement takes.
    announcing: Option<(u64, u64, bool)>,
    /// This run of the group has led: only such a run takes its
    /// placements' answers, or announces as it steps down.
    led: bool,
}

/// A snapshot stream this replica runs to a follower, as leader.
struct Stream {
    term: u64,
    index: u64,
    /// Where the follower's acknowledgements go: the next chunk it wants.
    acks: smol::channel::Sender<u64>,
    /// When the follower had staged every chunk: the stream is held until
    /// it switches (its match reaches the index) or [`STREAM_HOLD`] passes.
    staged: Option<Instant>,
}

/// A snapshot this replica stages from its leader, named by the leader's
/// term and the snapshot's index.
struct Install {
    term: u64,
    index: u64,
    snapshot_term: u64,
    /// The epoch its rows are staged under.
    epoch: u8,
    /// The next chunk it wants.
    next: u64,
    manifest: Manifest,
    /// The programs its installed instances name.
    programs: BTreeSet<[u8; 32]>,
    /// Every chunk is staged.
    staged: bool,
    /// When the last chunk was staged.
    since: Instant,
}

enum Event {
    Input(Input),
    Local(Local),
    Closed,
    Timer,
}

impl Driver {
    /// Recover the group from the store, in order: the writer told what is
    /// applied, the log cut at a lost blob, stale epochs dropped, then the
    /// core.
    async fn start(inner: Arc<Inner>, shared: Arc<Shared>) -> Result<Self, String> {
        let agent = shared.agent;
        let store = &inner.store;
        let failed = |error: fjall::Error| error.to_string();
        let rows = store.raft(agent).map_err(failed)?;
        inner.storage.recovered(agent, rows.applied);
        let cut = raft::recovery_cut(store, &inner.blobs, agent).map_err(failed)?;
        inner.storage.commit(cut.changes).await?;
        for epoch in store.stale_epochs(agent).map_err(failed)? {
            inner
                .storage
                .commit(vec![Change::DropEpoch {
                    agent,
                    epoch,
                    limit: usize::MAX,
                }])
                .await?;
        }
        let rows = store.raft(agent).map_err(failed)?;
        let last_index = rows
            .log
            .last()
            .map_or(rows.log_start.0, |(index, _)| *index);
        let applied = rows.applied;
        // What the log still holds of the commit: a cut at a lost blob may
        // have taken the rest.
        let recovered = rows.hard.commit.min(last_index).max(applied);
        let mut config = RaftConfig::new(inner.number, shared.members.clone(), shared.identity);
        config.election_timeout_ms = inner.election_timeout_ms;
        config.heartbeat_interval_ms = inner.heartbeat_ms;
        config.compact_hysteresis = inner.compact_every;
        config.compact_bytes = inner.compact_bytes;
        config.snapshot_timeout_ms = inner.snapshot_timeout_ms;
        // The pair heartbeat vouches for an idle group's leader. An idle
        // leader goes round once per check-quorum window, which keeps it
        // listed.
        config.idle_heartbeats = false;
        config.check_quorum = true;
        let core = Core::new(config, raft::recovered(rows), 0, rand_seed());
        let established = established(&core, inner.number);
        shared.update(|state| {
            state.written = last_index;
            state.applied = applied;
            state.recovered = recovered;
            state.established = established;
        });
        Ok(Self {
            agent,
            core,
            start: Instant::now(),
            reports: EntryReports::default(),
            writes: VecDeque::new(),
            last_index,
            proposals: HashMap::new(),
            reads: HashMap::new(),
            next_token: 0,
            asked: None,
            turn: 0,
            retired: false,
            stalled: false,
            streams: HashMap::new(),
            install: None,
            install_missing: Vec::new(),
            chunks: VecDeque::new(),
            compact_bound: 0,
            compact_due: false,
            memberships: HashMap::new(),
            announced: None,
            announcing: None,
            led: false,
            inner,
            shared,
        })
    }

    fn now(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
    }

    /// Vouch for this replica's leader and members from the node's pair
    /// heartbeats.
    fn vouch(&mut self, now: u64) {
        let start = self.start;
        let at = |instant: Instant| instant.saturating_duration_since(start).as_millis() as u64;
        let agent = self.agent;
        let table = self
            .inner
            .liveness
            .table
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.core.vouch(
            now,
            |node, term| table.listed(node, &agent, term).map(at),
            |node| table.heard_at(node).map(at),
        );
    }

    async fn run(
        mut self,
        inbox: smol::channel::Receiver<Input>,
        local: smol::channel::Receiver<Local>,
    ) {
        if self.process().await {
            loop {
                if self.shared.state().stopped {
                    break;
                }
                self.shared.woke.store(
                    self.inner.liveness.elapsed(),
                    std::sync::atomic::Ordering::Relaxed,
                );
                // An idle core may need no tick at all.
                let mut wake = self
                    .start
                    .checked_add(Duration::from_millis(self.core.next_deadline()));
                let mut sooner = |at: Instant| {
                    wake = Some(wake.map_or(at, |wake| wake.min(at)));
                };
                if let Some((asked, _)) = &self.asked {
                    sooner(*asked + BLOB_RETRY);
                }
                if let Some(install) = &self.install {
                    sooner(install.since + INSTALL_IDLE);
                }
                for staged in self.streams.values().filter_map(|stream| stream.staged) {
                    sooner(staged + STREAM_HOLD);
                }
                let event = async {
                    match local.recv().await {
                        Ok(local) => Event::Local(local),
                        Err(_) => Event::Closed,
                    }
                }
                .or(async {
                    match inbox.recv().await {
                        Ok(input) => Event::Input(input),
                        Err(_) => Event::Closed,
                    }
                })
                .or(async {
                    match wake {
                        Some(wake) => smol::Timer::at(wake).await,
                        None => smol::Timer::never().await,
                    };
                    Event::Timer
                })
                .await;
                let now = self.now();
                // A deadline due runs only once the pair heartbeat had its
                // say.
                if self.core.next_deadline() <= now {
                    self.vouch(now);
                }
                self.core.tick(now);
                match event {
                    Event::Closed => break,
                    Event::Timer => {}
                    Event::Local(local) => self.take_local(local),
                    Event::Input(input) => self.take(input),
                }
                // Everything already queued joins this round, so the core
                // joins it in one write.
                while let Ok(local) = local.try_recv() {
                    self.take_local(local);
                }
                let mut taken = 0;
                while taken < ROUND {
                    let Ok(input) = inbox.try_recv() else {
                        break;
                    };
                    self.take(input);
                    taken += 1;
                }
                self.report_health();
                self.core
                    .durably_applied(self.inner.storage.durably_applied(self.agent));
                // A replica a change removed learns of it from the
                // directory, which tells every node until each holds it,
                // one that is down once it returns: the group does not wait
                // for the replica's own acknowledgement.
                self.core.release_retiring_voters();
                self.settle_streams();
                if !self.process().await
                    || !self.stage().await
                    || !self.compact().await
                    || !self.process().await
                {
                    break;
                }
                self.settle_membership().await;
                self.fetch_blobs();
            }
        }
        // A caller who sees the group gone sees it lead nothing, and a
        // proposal still queued hears so.
        self.shared.update(|state| {
            state.role = Role::Follower;
            state.leading_from = None;
            state.stopped = true;
        });
        local.close();
        while let Ok(local) = local.try_recv() {
            match local {
                Local::Propose { answer, .. } => {
                    let _ = answer.try_send((Err(ProposeError::Stopped), Instant::now()));
                }
                Local::ReadIndex { answer } => {
                    let _ = answer.try_send(Err(ReadIndexError::Stopped));
                }
                Local::ChangeMembership { answer, .. } => {
                    let _ = answer.try_send(Err(ChangeMembershipError::Stopped));
                }
                Local::Retire
                | Local::StreamEnded { .. }
                | Local::Probe(_)
                | Local::Wake
                | Local::Placed { .. } => {}
            }
        }
        for (_, answer) in self.proposals.drain() {
            let _ = answer.try_send((Err(ProposeError::Stopped), Instant::now()));
        }
        for (_, answer) in self.reads.drain() {
            let _ = answer.try_send(Err(ReadIndexError::Stopped));
        }
        for (_, answer) in self.memberships.drain() {
            let _ = answer.try_send(Err(ChangeMembershipError::Stopped));
        }
    }

    fn take(&mut self, input: Input) {
        match input {
            Input::Raft { from, message } => {
                // A pre-vote meets stickiness as fresh as the pair
                // heartbeat makes it.
                if matches!(message, vos_raft::Message::PreVote { .. }) {
                    let now = self.now();
                    self.vouch(now);
                }
                self.core.receive(from, message)
            }
            Input::Blobs => self.report_ready(),
            Input::Chunk { from, chunk } => self.chunks.push_back((from, chunk)),
            Input::ChunkAck { from, ack } => {
                if let Some(stream) = self.streams.get(&from)
                    && (ack.agent, ack.term, ack.index) == (self.agent, stream.term, stream.index)
                {
                    let _ = stream.acks.try_send(ack.next);
                }
            }
        }
    }

    fn take_local(&mut self, local: Local) {
        match local {
            // A proposal from another leadership never lands in this one.
            Local::Propose {
                term,
                payload,
                answer,
            } => {
                if self.core.role() != Role::Leader || self.core.status().current_term != term {
                    let _ = answer.try_send((Err(ProposeError::NotLeader), Instant::now()));
                    return;
                }
                let token = self.next_token;
                self.next_token += 1;
                self.proposals.insert(token, answer);
                self.core.propose(token, payload);
            }
            Local::Retire => self.retired = true,
            Local::Probe(node) => self.core.probe(node),
            Local::Wake => {}
            Local::Placed { order, kept } => {
                if self.announcing == Some(order) {
                    self.announcing = None;
                }
                // One not kept is tried again the next round. An answer
                // for an earlier run of the group is no concern of a run
                // that never led.
                if kept && self.led {
                    self.announced = Some(self.announced.map_or(order, |held| held.max(order)));
                }
            }
            Local::ReadIndex { answer } => {
                let token = self.next_token;
                self.next_token += 1;
                self.reads.insert(token, answer);
                self.core.read_index(token, Some(READ_INDEX_MS));
            }
            Local::ChangeMembership {
                current,
                members,
                answer,
            } => {
                // The caller read the members from the directory, which
                // may trail the core just after an election.
                let status = self.core.status();
                let mut held = status.members;
                held.sort_unstable();
                if status.joint_old.is_some() || held != current {
                    let _ = answer.try_send(Err(ChangeMembershipError::InProgress));
                    return;
                }
                let token = self.next_token;
                self.next_token += 1;
                self.memberships.insert(token, answer);
                self.core.change_membership(token, members);
            }
            Local::StreamEnded {
                to,
                term,
                index,
                done,
            } => {
                let Some(stream) = self
                    .streams
                    .get_mut(&to)
                    .filter(|stream| (stream.term, stream.index) == (term, index))
                else {
                    return;
                };
                if done {
                    // Held until its follower switches: the log keeps the
                    // entries after it, and no other stream displaces it.
                    stream.staged = Some(Instant::now());
                } else {
                    self.streams.remove(&to);
                    self.core.snapshot_failed(to);
                    self.compact_due = true;
                }
            }
        }
    }

    /// Tell the core whether its writer is stalled. A replica whose leader
    /// loop stopped for good (`retired`) is reported as stalled on purpose:
    /// the core then hands leadership over and does not campaign.
    fn report_health(&mut self) {
        let stalled = self.retired || self.inner.storage.stalled();
        if stalled != self.stalled {
            self.stalled = stalled;
            self.core.writer_health(stalled);
        }
    }

    /// Run the core's actions until it has none. False when storage
    /// failed: the node halts. A round's messages go out before its
    /// writes are waited on: the core holds back whatever must wait for
    /// one, and a leader's appends need not wait for its own fsync.
    async fn process(&mut self) -> bool {
        loop {
            let actions = self.core.take_actions();
            if actions.is_empty() {
                return true;
            }
            let (sends, rest): (Vec<_>, Vec<_>) = actions
                .into_iter()
                .partition(|action| matches!(action, Action::Send { .. }));
            for action in sends.into_iter().chain(rest) {
                if !self.act(action).await {
                    return false;
                }
            }
        }
    }

    async fn act(&mut self, action: Action<NodeNumber>) -> bool {
        match action {
            Action::Write(write) => return self.write(write).await,
            Action::Send { to, message } => {
                if let Some(network) = &self.inner.network {
                    let frame = PeerMessage::Raft {
                        agent: self.agent,
                        message: crate::peer::to_wire(&message),
                    }
                    .encode();
                    // Refused, it is dropped: Raft sends again.
                    let _ = network.send(to, Class::Consensus, u64::from(self.agent.0), frame);
                }
            }
            Action::LoadEntries(load) => {
                let store = self.inner.store.clone();
                let agent = self.agent;
                let request = load;
                let loaded = self
                    .inner
                    .offload(move || raft::load(&store, agent, &request))
                    .await;
                match loaded {
                    Some(Ok(entries)) => self.core.loaded(load, entries),
                    // Nothing loaded: the core forgets the load, and asks
                    // again when its peers next answer.
                    _ => {
                        tracing::warn!(agent = self.agent.0, "a log load failed");
                        self.core.loaded(load, Vec::new());
                    }
                }
            }
            Action::Committed { index } => self.shared.update(|state| {
                state.commit = index;
                state.commit_at = Some(Instant::now());
            }),
            Action::CompactBound { through, .. } => {
                self.compact_bound = self.compact_bound.max(through);
                self.compact_due = true;
            }
            Action::SendSnapshot { to, .. } => self.send_snapshot(to),
            Action::Answer(Answer::Propose { token, result }) => {
                if let Some(answer) = self.proposals.remove(&token) {
                    let _ = answer.try_send((result, Instant::now()));
                }
            }
            Action::Answer(Answer::ReadIndex { token, result }) => {
                if let Some(answer) = self.reads.remove(&token) {
                    let _ = answer.try_send(result);
                }
            }
            Action::Answer(Answer::ChangeMembership { token, result }) => {
                if let Some(answer) = self.memberships.remove(&token) {
                    let _ = answer.try_send(result);
                }
            }
            Action::Changed { term, role, leader } => {
                // A leadership's streams end with it.
                if role != Role::Leader {
                    self.streams.clear();
                } else {
                    self.led = true;
                }
                // Becoming leader, the core appended its term's no-op last.
                let leading_from =
                    (role == Role::Leader).then(|| self.core.status().last_log_index);
                self.shared.update(|state| {
                    state.role = role;
                    state.term = term;
                    state.leader = leader;
                    state.leading_from = leading_from;
                });
                if role != Role::Leader {
                    // A leader that removed itself steps down as the final
                    // configuration commits: it says so itself, at once,
                    // rather than leave it to the next leader's election.
                    let status = self.core.status();
                    let me = self.inner.number;
                    let removed = self.led
                        && (self.announced.is_some() || self.announcing.is_some())
                        && status.joint_old.is_none()
                        && !status.members.contains(&me)
                        && status.commit_index >= status.active_config_index.unwrap_or(0);
                    if removed {
                        self.announce_placement().await;
                    }
                    self.announced = None;
                    self.announcing = None;
                    // It retires once it steps down; a group stopping does
                    // not.
                    if !self.shared.state().stopped {
                        self.inner.reconsider(self.agent);
                    }
                }
            }
        }
        true
    }

    async fn write(&mut self, write: Write<NodeNumber>) -> bool {
        let changes = raft::changes(self.agent, &write);
        if let Err(error) = self.inner.storage.commit(changes).await {
            tracing::error!(
                agent = self.agent.0,
                "a log write failed ({error}); the node stops and needs a restart"
            );
            self.inner.halt();
            return false;
        }
        self.core.durable(write.seq);
        if let Some(after) = write.truncate_after {
            // What was written past the cut is gone, even where its write
            // is still waiting for blobs.
            self.last_index = self.last_index.min(after);
            for (_, last) in &mut self.writes {
                *last = (*last).min(after);
            }
            self.shared
                .update(|state| state.written = state.written.min(after));
        }
        if let Some(last) = write.entries.last() {
            self.last_index = last.index;
        }
        self.writes.push_back((write.seq, self.last_index));
        let named: Vec<[u8; 32]> = write
            .entries
            .iter()
            .flat_map(|entry| raft::to_store(entry).blobs)
            .map(|blob| blob.hash)
            .collect();
        let stored: BTreeSet<[u8; 32]> = if named.is_empty() {
            BTreeSet::new()
        } else {
            // Touched, a blob stays while an entry comes to rely on it.
            match self.inner.blobs.touch(named).await {
                Ok(stored) => stored.into_iter().collect(),
                Err(error) => {
                    tracing::warn!(agent = self.agent.0, "a blob touch failed: {error}");
                    BTreeSet::new()
                }
            }
        };
        self.reports.written(&write, |hash| stored.contains(hash));
        self.report_ready();
        true
    }

    /// Report the writes whose entries now have their blobs.
    fn report_ready(&mut self) {
        let blobs = &self.inner.blobs;
        let Some(seq) = self
            .reports
            .ready(|hash| blobs.contains(hash).unwrap_or(false))
        else {
            return;
        };
        self.core.entries_durable(seq);
        let mut written = None;
        while let Some(&(at, last)) = self.writes.front() {
            if at > seq {
                break;
            }
            written = Some(last);
            self.writes.pop_front();
        }
        if let Some(written) = written {
            self.shared.update(|state| state.written = written);
        }
    }

    /// Note when this replica holds a committed configuration naming it,
    /// and, leading, announce where the agent runs whenever that changes.
    async fn settle_membership(&mut self) {
        if established(&self.core, self.inner.number) && !self.shared.state().established {
            self.shared.update(|state| state.established = true);
        }
        if self.core.role() != Role::Leader {
            return;
        }
        self.announce_placement().await;
    }

    /// Announce where the agent runs, as this replica's core has it, when
    /// that changed since it last did.
    async fn announce_placement(&mut self) {
        let status = self.core.status();
        let index = status.active_config_index.unwrap_or(0);
        let mut replicas = status.members.clone();
        replicas.extend(status.joint_old.iter().flatten().copied());
        replicas.sort_unstable();
        replicas.dedup();
        // The configuration before, or, once that is compacted away, the
        // log's first, which may be this one. It matters while a placement is uncommitted, and
        // names a leader the change removed: the core keeps it until the
        // removal is confirmed.
        let before = if index == 0 {
            Vec::new()
        } else {
            self.core
                .config_at(index - 1)
                .map(|record| {
                    let mut nodes = record.current;
                    nodes.extend(record.joint_old.unwrap_or_default());
                    nodes.sort_unstable();
                    nodes.dedup();
                    nodes
                })
                .unwrap_or_default()
        };
        let placement = Placement {
            replicas,
            before,
            term: status.current_term,
            index,
            joint: status.joint_old.is_some(),
            committed: status.commit_index >= index,
        };
        let order = placement.order();
        if self.announced == Some(order) || self.announcing == Some(order) {
            return;
        }
        self.announcing = Some(order);
        let inner = Arc::clone(&self.inner);
        let agent = self.agent;
        // The answer goes to whichever run of the agent's group is there
        // then. A later run that has led, at a later term, takes it as one
        // more placement known kept, which changes nothing it announces; a
        // later run that never led ignores it.
        self.inner.spawn(async move {
            let kept = inner.place(agent, placement).await;
            inner.propose(agent, Local::Placed { order, kept });
        });
    }

    /// Release each stream whose follower switched to its snapshot, or
    /// that waited for it too long: the core then sends again as soon as
    /// it would, not once its own deadline passes.
    fn settle_streams(&mut self) {
        let core = &self.core;
        let mut unswitched = Vec::new();
        let before = self.streams.len();
        self.streams.retain(|to, stream| match stream.staged {
            Some(staged) => {
                let switched = core.match_index(*to).unwrap_or(0) >= stream.index;
                let held = !switched && staged.elapsed() < STREAM_HOLD;
                if !switched && !held {
                    unswitched.push(*to);
                }
                held
            }
            None => true,
        });
        for to in unswitched {
            self.core.snapshot_failed(to);
        }
        if self.streams.len() < before {
            self.compact_due = true;
        }
    }

    /// Compact the log as far as the core's bound allows, less a tail a
    /// follower a little behind still gets entries from, and never past a
    /// snapshot being streamed: its follower needs the entries after it.
    /// The configuration recorded is the one in effect where it stops.
    async fn compact(&mut self) -> bool {
        if !std::mem::take(&mut self.compact_due) {
            return true;
        }
        let mut point = self.core.compaction_point(
            self.compact_bound,
            self.inner.compact_tail,
            self.inner.compact_tail_bytes,
        );
        if let Some(lowest) = self.streams.values().map(|stream| stream.index).min() {
            point = point.min(lowest);
        }
        if point <= self.core.status().snap_last_index {
            return true;
        }
        let configuration = self.core.config_at(point);
        let change =
            match raft::compaction(&self.inner.store, self.agent, point, configuration.as_ref()) {
                Ok(Some(change)) => change,
                Ok(None) => return true,
                Err(error) => {
                    tracing::warn!(agent = self.agent.0, "a compaction read failed: {error}");
                    return true;
                }
            };
        // A compaction is never needed: refused, the log stays longer.
        if let Err(error) = self.inner.storage.commit(vec![change]).await {
            tracing::warn!(agent = self.agent.0, "a compaction was refused: {error}");
            return true;
        }
        self.core.compacted(point);
        true
    }

    /// Stream this replica's state to `to`, which needs entries the log no
    /// longer holds: exported at its applied index, with the configuration
    /// in effect there. One stream per follower: the core asks again while
    /// one runs, and is not heard.
    fn send_snapshot(&mut self, to: NodeNumber) {
        if self.streams.contains_key(&to) {
            return;
        }
        let export = match self.inner.store.export(self.agent) {
            Ok(export) => export,
            Err(error) => {
                tracing::warn!(agent = self.agent.0, "a snapshot export failed: {error}");
                self.core.snapshot_failed(to);
                return;
            }
        };
        let configuration = self
            .core
            .config_at(export.applied)
            .map(|record| Configuration {
                members: record.current,
                joint_old: record.joint_old,
                index: record.log_index.unwrap_or(0),
            });
        let manifest = Manifest {
            configuration,
            last_result: export.last_result,
        };
        let term = self.core.status().current_term;
        let index = export.applied;
        let (acks, acked) = smol::channel::unbounded();
        self.streams.insert(
            to,
            Stream {
                term,
                index,
                acks,
                staged: None,
            },
        );
        self.inner
            .streamed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let inner = Arc::clone(&self.inner);
        let shared = Arc::clone(&self.shared);
        let agent = self.agent;
        self.inner.spawn(async move {
            let done = stream(&inner, &shared, (to, term), export, manifest, acked).await;
            inner.propose(
                agent,
                Local::StreamEnded {
                    to,
                    term,
                    index,
                    done,
                },
            );
        });
    }

    /// Stage the snapshot chunks taken this round, and switch to the
    /// snapshot once it is whole and its programs are here. False when the
    /// node must halt.
    async fn stage(&mut self) -> bool {
        if self.core.role() == Role::Leader {
            self.chunks.clear();
            self.abandon().await;
            return true;
        }
        while let Some((from, chunk)) = self.chunks.pop_front() {
            self.stage_chunk(from, chunk).await;
        }
        if self
            .install
            .as_ref()
            .is_some_and(|install| install.since.elapsed() >= INSTALL_IDLE)
        {
            tracing::warn!(agent = self.agent.0, "a snapshot stopped arriving; dropped");
            self.abandon().await;
        }
        if self.install.as_ref().is_some_and(|install| install.staged) {
            return self.switch().await;
        }
        true
    }

    async fn stage_chunk(&mut self, from: NodeNumber, chunk: SnapshotChunk) {
        let name = (chunk.term, chunk.index);
        // Not acknowledged: the leader's appends correct its view of this
        // replica, and the stream falls silent.
        if chunk.agent != self.agent || chunk.index <= self.shared.state().applied {
            return;
        }
        let current = self
            .install
            .as_ref()
            .map(|install| (install.term, install.index));
        // A late chunk of a stream a newer one replaced.
        if current.is_some_and(|current| name < current) {
            return;
        }
        if current != Some(name) {
            // A snapshot staged whole switches, or is dropped once idle,
            // before a newer stream takes its place.
            if self.install.as_ref().is_some_and(|install| install.staged) {
                return;
            }
            // A newer stream, from its first chunk: the follower wants that.
            if chunk.sequence != 0 {
                self.ack(from, name, 0);
                return;
            }
            self.abandon().await;
            let Some(epoch) = self.empty_epoch() else {
                return;
            };
            self.install = Some(Install {
                term: chunk.term,
                index: chunk.index,
                snapshot_term: chunk.snapshot_term,
                epoch,
                next: 0,
                manifest: chunk.manifest.clone().unwrap_or(Manifest {
                    configuration: None,
                    last_result: None,
                }),
                programs: BTreeSet::new(),
                staged: false,
                since: Instant::now(),
            });
        }
        let install = self.install.as_mut().expect("an install");
        if install.staged || chunk.sequence != install.next {
            let next = install.next;
            self.ack(from, name, next);
            return;
        }
        let prefix = keys::installed_prefix();
        install.programs.extend(programs(
            chunk
                .rows
                .iter()
                .filter(|(key, _)| key.starts_with(&prefix))
                .map(|(_, value)| value),
        ));
        let stage = Change::Stage {
            agent: self.agent,
            epoch: install.epoch,
            first: chunk.sequence == 0,
            rows: chunk.rows,
        };
        if let Err(error) = self.inner.storage.commit(vec![stage]).await {
            tracing::warn!(
                agent = self.agent.0,
                "a snapshot chunk was not staged: {error}"
            );
            self.abandon().await;
            return;
        }
        let install = self.install.as_mut().expect("an install");
        install.next += 1;
        install.since = Instant::now();
        install.staged = chunk.last;
        let next = install.next;
        self.ack(from, name, next);
    }

    /// Switch to the staged snapshot, in one synced batch with the core's
    /// rows, its last result and its programs' pins, once those programs
    /// are here.
    async fn switch(&mut self) -> bool {
        let Some(install) = self.install.as_ref() else {
            return true;
        };
        let named: Vec<[u8; 32]> = install.programs.iter().copied().collect();
        let blobs = &self.inner.blobs;
        self.install_missing = named
            .iter()
            .filter(|hash| !blobs.contains(hash).unwrap_or(false))
            .copied()
            .collect();
        // Once every program is here, each is touched: it stays while the
        // switch comes to pin it, as the blob writer orders the touch with
        // a collection's removals. One removed meanwhile is wanted again.
        if self.install_missing.is_empty() && !named.is_empty() {
            match blobs.touch(named.clone()).await {
                Ok(stored) => {
                    self.install_missing = named
                        .into_iter()
                        .filter(|hash| !stored.contains(hash))
                        .collect();
                }
                Err(error) => {
                    tracing::warn!(agent = self.agent.0, "a blob touch failed: {error}");
                    return true;
                }
            }
        }
        if !self.install_missing.is_empty() {
            self.inner.want(self.agent, &self.install_missing);
            return true;
        }
        let install = self.install.take().expect("an install");
        let configuration =
            install
                .manifest
                .configuration
                .clone()
                .map(|configuration| SnapshotConfiguration {
                    members: configuration.members,
                    joint_old: configuration.joint_old,
                    index: configuration.index,
                });
        let switch =
            self.core
                .snapshot_switch(install.index, install.snapshot_term, configuration.as_ref());
        let keeps_suffix = switch.truncate_after.is_none();
        let snapshot = self.inner.store.snapshot();
        let (old_epoch, before) = match snapshot.epoch(self.agent).and_then(|epoch| {
            let mut values = Vec::new();
            for row in snapshot.scan(self.agent, &keys::installed_prefix(), None) {
                values.push(row?.1);
            }
            Ok((epoch, programs(values.iter())))
        }) {
            Ok(read) => read,
            Err(error) => {
                tracing::warn!(
                    agent = self.agent.0,
                    "the state before a switch is unreadable: {error}"
                );
                self.install = Some(install);
                return true;
            }
        };
        let mut changes = vec![raft::switch_change(
            self.agent,
            install.epoch,
            install.index,
            install.snapshot_term,
            &switch,
        )];
        if let Some((time, seed)) = install.manifest.last_result {
            changes.push(Change::LastResult {
                agent: self.agent,
                time,
                seed,
            });
        }
        let agent = self.agent;
        changes.extend(
            install
                .programs
                .difference(&before)
                .map(|hash| Change::Pin { hash: *hash, agent }),
        );
        changes.extend(
            before
                .difference(&install.programs)
                .map(|hash| Change::Unpin { hash: *hash, agent }),
        );
        let applying = self.shared.applying.lock().await;
        let unpinned = unpinned(&changes);
        if let Err(error) = self.inner.storage.commit(changes).await {
            drop(applying);
            // A failed flush may have written the switch: the staged epoch
            // may be the store's now, and is not to be dropped.
            if self.inner.storage.failed() {
                tracing::error!(
                    agent = self.agent.0,
                    "a snapshot switch failed ({error}); the node stops and needs a restart"
                );
                self.inner.halt();
                return false;
            }
            tracing::warn!(
                agent = self.agent.0,
                "a snapshot switch was refused: {error}"
            );
            self.install = Some(install);
            self.abandon().await;
            return true;
        }
        self.inner.evict(&unpinned);
        let index = install.index;
        self.core
            .snapshot_installed(index, install.snapshot_term, configuration);
        self.reports.switched(index, keeps_suffix);
        if keeps_suffix {
            self.last_index = self.last_index.max(index);
        } else {
            self.last_index = index;
            for (_, last) in &mut self.writes {
                *last = (*last).min(index);
            }
        }
        self.shared.update(|state| {
            state.applied = state.applied.max(index);
            state.commit = state.commit.max(index);
            state.written = if keeps_suffix {
                state.written.max(index)
            } else {
                index
            };
        });
        drop(applying);
        self.inner
            .installed
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.drop_epoch(old_epoch);
        true
    }

    /// Drop the snapshot being staged, if any, in the background.
    async fn abandon(&mut self) {
        let Some(install) = self.install.take() else {
            return;
        };
        self.install_missing.clear();
        self.drop_epoch(install.epoch);
    }

    /// An epoch past the current one that holds no rows, for a snapshot to
    /// be staged under: one an earlier install left is being dropped in the
    /// background, and a stream never waits for it.
    fn empty_epoch(&self) -> Option<u8> {
        empty_epoch(&self.inner, self.agent)
    }

    /// Remove an epoch a switch, or an abandoned install, left behind, in
    /// the background: marked as dropped before the drop can run.
    fn drop_epoch(&self, epoch: u8) {
        let inner = Arc::clone(&self.inner);
        let agent = self.agent;
        self.inner.dropping(agent, epoch);
        self.inner.spawn(async move {
            drop_epoch(&inner, agent, epoch).await;
            inner.dropped(agent, epoch);
        });
    }

    /// Tell the leader `to` which chunk of the stream `name` this replica
    /// wants next.
    fn ack(&self, to: NodeNumber, (term, index): (u64, u64), next: u64) {
        self.inner.send(
            to,
            Class::Consensus,
            &PeerMessage::SnapshotAck(SnapshotAck {
                agent: self.agent,
                term,
                index,
                next,
            }),
        );
    }

    /// Ask for the blobs the group's entries wait for: the leader first,
    /// then each other member in turn.
    fn fetch_blobs(&mut self) {
        let mut missing = self.reports.missing();
        missing.extend(
            self.install_missing
                .iter()
                .filter(|hash| !missing.contains(hash))
                .copied()
                .collect::<Vec<_>>(),
        );
        if missing.is_empty() {
            self.asked = None;
            return;
        }
        let due = self
            .asked
            .as_ref()
            .is_none_or(|(at, asked)| at.elapsed() >= BLOB_RETRY || *asked != missing);
        if !due {
            return;
        }
        let Some(network) = &self.inner.network else {
            return;
        };
        let me = self.inner.number;
        let others: Vec<NodeNumber> = self
            .inner
            .placement(self.agent)
            .map(|placement| placement.replicas)
            .unwrap_or_default()
            .into_iter()
            .filter(|node| *node != me)
            .collect();
        if others.is_empty() {
            return;
        }
        let leader = self.shared.state().leader.filter(|leader| *leader != me);
        let target = match (self.turn, leader) {
            (0, Some(leader)) => leader,
            (turn, _) => others[turn % others.len()],
        };
        self.turn += 1;
        self.inner.want(self.agent, &missing);
        let frame = PeerMessage::BlobRequest {
            agent: self.agent,
            hashes: missing.clone(),
        }
        .encode();
        let _ = network.send(target, Class::Requests, u64::from(self.agent.0), frame);
        self.asked = Some((Instant::now(), missing));
    }
}

/// Remove `agent`'s rows under the old `epoch`, a few thousand a write,
/// until it holds none. Its caller marks the epoch as dropped first
/// (`Inner::dropping`): an epoch emptied by one pass, and chosen for a new
/// install before the next, would lose the install's rows.
async fn drop_epoch(inner: &Inner, agent: AgentId, epoch: u8) {
    loop {
        let drop = Change::DropEpoch {
            agent,
            epoch,
            limit: DROP_ROWS,
        };
        if inner.storage.commit(vec![drop]).await.is_err() {
            return;
        }
        match inner.store.stale_epochs(agent) {
            Ok(stale) if stale.contains(&epoch) => {}
            _ => return,
        }
    }
}

/// An epoch of `agent`'s past its current one that holds no rows, and that
/// no drop runs on.
pub(crate) fn empty_epoch(inner: &Inner, agent: AgentId) -> Option<u8> {
    let read = inner
        .store
        .snapshot()
        .epoch(agent)
        .and_then(|current| Ok((current, inner.store.stale_epochs(agent)?)));
    let (current, stale) = match read {
        Ok(read) => read,
        Err(error) => {
            tracing::warn!(agent = agent.0, "the epochs are unreadable: {error}");
            return None;
        }
    };
    let mut epoch = next_epoch(current);
    while stale.contains(&epoch) || inner.is_dropping(agent, epoch) {
        epoch = next_epoch(epoch);
        if epoch == current {
            return None;
        }
    }
    Some(epoch)
}

/// Whether `core` holds a committed configuration naming `me`.
fn established(core: &Core<NodeNumber>, me: NodeNumber) -> bool {
    let status = core.status();
    let named = status.members.contains(&me)
        || status
            .joint_old
            .as_ref()
            .is_some_and(|old| old.contains(&me));
    named && status.commit_index >= status.active_config_index.unwrap_or(0)
}

/// Remove every stale epoch of `agent`'s, as [`drop_epoch`] does.
pub(crate) async fn drop_stale_epochs(inner: &Inner, agent: AgentId) {
    let Ok(stale) = inner.store.stale_epochs(agent) else {
        return;
    };
    for &epoch in &stale {
        inner.dropping(agent, epoch);
    }
    for epoch in stale {
        drop_epoch(inner, agent, epoch).await;
        inner.dropped(agent, epoch);
    }
}

/// Stream `export` to `to` as leader in `term`, a few chunks past what
/// it acknowledged: true once it staged every chunk, false when it fell
/// silent or the leadership ended. A stream ends with a chunk of no rows.
async fn stream(
    inner: &Inner,
    shared: &Shared,
    (to, term): (NodeNumber, u64),
    mut export: Export,
    manifest: Manifest,
    acked: smol::channel::Receiver<u64>,
) -> bool {
    let agent = shared.agent;
    let (index, snapshot_term) = (export.applied, export.term);
    // Chunks sent and not yet acknowledged, by sequence.
    let mut window: std::collections::BTreeMap<u64, Vec<u8>> = std::collections::BTreeMap::new();
    let mut read = 0;
    let mut last = None;
    let mut wanted = 0;
    let mut moved = Instant::now();
    // When the chunk the follower still wants was last sent again.
    let mut resent: Option<Instant> = None;
    let mut manifest = Some(manifest);
    let send = |frame: Vec<u8>| async move {
        let Some(network) = &inner.network else {
            return;
        };
        let room = async {
            network.ready(to, Class::Bulk).await;
            true
        };
        let late = async {
            smol::Timer::after(CHUNK_RESEND).await;
            false
        };
        if room.or(late).await {
            // Refused, it is sent again when no acknowledgement moves.
            let _ = network.send(to, Class::Bulk, u64::from(agent.0), frame);
        }
    };
    loop {
        while last.is_none() && read < wanted + CHUNKS_AHEAD {
            let bytes = inner.snapshot_chunk;
            let Some((back, rows)) = inner
                .offload(move || {
                    let rows = export.next_chunk(bytes);
                    (export, rows)
                })
                .await
            else {
                return false;
            };
            export = back;
            let (rows, end) = match rows {
                Ok(Some(rows)) => (rows, false),
                Ok(None) => (Vec::new(), true),
                Err(error) => {
                    tracing::warn!(agent = agent.0, "a snapshot read failed: {error}");
                    return false;
                }
            };
            let frame = PeerMessage::SnapshotChunk(SnapshotChunk {
                agent,
                term,
                index,
                snapshot_term,
                sequence: read,
                manifest: if read == 0 { manifest.take() } else { None },
                rows,
                last: end,
            })
            .encode();
            window.insert(read, frame.clone());
            let delay = inner.hooks.delay_chunk();
            if !delay.is_zero() {
                smol::Timer::after(delay).await;
            }
            send(frame).await;
            if end {
                last = Some(read);
            }
            read += 1;
        }
        if last.is_some_and(|last| wanted > last) {
            return true;
        }
        let ack = async { Some(acked.recv().await.ok()) };
        let lost = async {
            shared
                .wait(|state| state.stopped || state.term != term || state.role != Role::Leader)
                .await;
            Some(None)
        };
        let quiet = async {
            smol::Timer::after(CHUNK_RESEND).await;
            None
        };
        match ack.or(lost).or(quiet).await {
            Some(Some(next)) if next > wanted => {
                wanted = next;
                moved = Instant::now();
                resent = None;
                window.retain(|sequence, _| *sequence >= next);
            }
            // The follower still wants `next`, having had a later chunk
            // first: that one goes again, at most once a while, so
            // reordered duplicates do not multiply.
            Some(Some(next)) if next == wanted => {
                if resent.is_none_or(|at| at.elapsed() >= CHUNK_RESEND)
                    && let Some(frame) = window.get(&next)
                {
                    send(frame.clone()).await;
                    resent = Some(Instant::now());
                }
            }
            // An acknowledgement overtaken by a later one.
            Some(Some(_)) => {}
            Some(None) => return false,
            None => {
                if moved.elapsed() >= STREAM_SILENCE {
                    return false;
                }
                for frame in window.values() {
                    send(frame.clone()).await;
                }
            }
        }
    }
}

fn rand_seed() -> u64 {
    let mut seed = [0u8; 8];
    getrandom::getrandom(&mut seed).expect("the operating system's randomness");
    u64::from_le_bytes(seed)
}

/// A leader's accumulate of its own result, run before proposing it, kept
/// so the apply of that entry need not run it again.
pub(crate) struct DryRun {
    /// The applied index the state was at.
    pub applied: u64,
    /// The entry's payload, which the applied entry must equal.
    pub payload: Vec<u8>,
    pub writes: Vec<StateWrite>,
}

/// Apply `shared`'s committed log in order until the group stops.
pub(crate) async fn apply(inner: Arc<Inner>, shared: Arc<Shared>) {
    let mut backoff = BACKOFF;
    loop {
        let state = shared
            .wait(|state| state.stopped || state.applied < state.commit.min(state.written))
            .await;
        if state.stopped {
            return;
        }
        // A snapshot switch may move the applied index past it meanwhile.
        let applying = shared.applying.lock().await;
        let state = shared.state();
        if state.applied >= state.commit.min(state.written) {
            continue;
        }
        let index = state.applied + 1;
        let applied = apply_one(&inner, &shared, index).await;
        if applied.is_ok() {
            shared.update(|state| {
                state.applied = index;
                state.applied_at = Some(Instant::now());
            });
        }
        drop(applying);
        match applied {
            Ok(()) => backoff = BACKOFF,
            Err(Fault::Storage(message)) => {
                tracing::error!(
                    agent = shared.agent.0,
                    "an apply failed ({message}); the node stops and needs a restart"
                );
                inner.halt();
                return;
            }
            Err(fault) => {
                // Never skipped: the same entry is applied again.
                tracing::error!(
                    agent = shared.agent.0,
                    index,
                    "the node failed an apply ({}); retrying in {backoff:?}",
                    fault.message()
                );
                let stopped = async {
                    shared.wait(|state| state.stopped).await;
                };
                stopped
                    .or(async {
                        smol::Timer::after(backoff).await;
                    })
                    .await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

/// Apply the entry at `index`: a work result's writes, from accumulate
/// with the creation record's gas; nothing for a no-op or a
/// configuration. A result accumulate fails on applies as no writes, on
/// every replica alike.
async fn apply_one(inner: &Arc<Inner>, shared: &Shared, index: u64) -> Result<(), Fault> {
    let agent = shared.agent;
    let infrastructure = |error: fjall::Error| Fault::Infrastructure(error.to_string());
    let entry = inner
        .store
        .log_entry(agent, index)
        .map_err(infrastructure)?
        .ok_or_else(|| Fault::Infrastructure(format!("the entry at {index} is missing")))?;
    let snapshot = Arc::new(inner.store.snapshot());
    let epoch = snapshot.epoch(agent).map_err(infrastructure)?;
    let mut rest = Vec::new();
    let writes = match entry.kind {
        EntryKind::Result => {
            let writes = if inner.hooks.fail_apply(agent, index, &entry.body) {
                Vec::new()
            } else {
                match inner.dry_run(agent, index, &entry) {
                    Some(writes) => writes,
                    None => accumulate(inner, shared, &snapshot, &entry, index).await?,
                }
            };
            let took = writes.iter().any(|write| write.key == keys::version());
            shared.record_outcome(index, took);
            if let Ok((result, _)) = WorkResult::decode(&entry.body) {
                rest.push(Change::LastResult {
                    agent,
                    time: result.time,
                    seed: result.seed,
                });
            }
            writes
        }
        EntryKind::NoOp | EntryKind::Configuration => Vec::new(),
    };
    let prefix = keys::installed_prefix();
    if writes.iter().any(|write| write.key.starts_with(&prefix)) {
        rest.extend(pins(&snapshot, agent, &writes).map_err(infrastructure)?);
    }
    let mut changes = vec![Change::Apply {
        agent,
        epoch,
        index,
        writes,
    }];
    changes.extend(rest);
    let unpinned = unpinned(&changes);
    inner
        .storage
        .commit(changes)
        .await
        .map_err(Fault::Storage)?;
    inner.evict(&unpinned);
    Ok(())
}

/// The programs `changes` unpin.
pub(crate) fn unpinned(changes: &[Change]) -> Vec<[u8; 32]> {
    changes
        .iter()
        .filter_map(|change| match change {
            Change::Unpin { hash, .. } => Some(*hash),
            _ => None,
        })
        .collect()
}

async fn accumulate(
    inner: &Arc<Inner>,
    shared: &Shared,
    snapshot: &Arc<FjallSnapshot>,
    entry: &LogEntry,
    index: u64,
) -> Result<Vec<StateWrite>, Fault> {
    let program = Arc::clone(&inner.program);
    let state = Arc::clone(snapshot);
    let agent = shared.agent;
    let gas = shared.record.accumulate_gas;
    let result = entry.body.clone();
    match ran(inner
        .executors
        .run(move || pvm::accumulate(&program, state, agent, result, gas))
        .await)
    {
        Ok(writes) => Ok(writes),
        Err(Fault::Agent(message)) => {
            tracing::warn!(
                agent = agent.0,
                index,
                "accumulate fails on the entry ({message}); it applies as no writes"
            );
            Ok(Vec::new())
        }
        Err(fault) => Err(fault),
    }
}

/// The pins an apply's `writes` change: every program the agent's
/// installed instances name is pinned, and one no instance names any more
/// is not.
fn pins(
    snapshot: &FjallSnapshot,
    agent: AgentId,
    writes: &[StateWrite],
) -> Result<Vec<Change>, fjall::Error> {
    let prefix = keys::installed_prefix();
    let mut rows: HashMap<Vec<u8>, Vec<u8>> = HashMap::new();
    for row in snapshot.scan(agent, &prefix, None) {
        let (key, value) = row?;
        rows.insert(key, value);
    }
    let before = programs(rows.values());
    for write in writes.iter().filter(|write| write.key.starts_with(&prefix)) {
        match &write.value {
            Some(value) => rows.insert(write.key.clone(), value.clone()),
            None => rows.remove(&write.key),
        };
    }
    let after = programs(rows.values());
    let pinned = after
        .difference(&before)
        .map(|hash| Change::Pin { hash: *hash, agent });
    let unpinned = before
        .difference(&after)
        .map(|hash| Change::Unpin { hash: *hash, agent });
    Ok(pinned.chain(unpinned).collect())
}

/// The programs installed rows name: each instance's, and its attestable
/// methods'.
pub(crate) fn programs<'a>(rows: impl Iterator<Item = &'a Vec<u8>>) -> BTreeSet<[u8; 32]> {
    let mut programs = BTreeSet::new();
    for value in rows {
        let Some((installed, _)) = unstored(value).and_then(|bytes| Installed::decode(bytes).ok())
        else {
            continue;
        };
        programs.insert(installed.program.0);
        programs.extend(installed.attestables.iter().map(|(_, hash)| hash.0));
    }
    programs
}
