//! An agent's replica group on this node: its consensus core, driven by
//! the node's log writer and the network, and its applier, which applies
//! the committed log in order, the same way on every replica.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vos_net::Class;
use vos_raft::core::{Action, Answer, Core, ProposeError, Write};
use vos_raft::{Config as RaftConfig, Message, Role};
use vos_wire::ids::AgentId;
use vos_wire::peer::{CreationRecord, NodeNumber, PeerMessage};
use vos_wire::records::{Installed, unstored};
use vos_wire::result::{WorkResult, Write as StateWrite};
use vos_wire::{Decode, Encode, keys};

use crate::node::{Inner, ran};
use crate::pvm::{self, Fault};
use crate::raft::{self, EntryReports};
use crate::storage::Change;
use crate::store::{EntryKind, FjallSnapshot, LogEntry, Store, View};

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

/// What a group hears from the network and the node: bounded, and
/// dropped when full.
pub(crate) enum Input {
    /// A Raft message from a peer, already checked.
    Raft {
        from: NodeNumber,
        message: Message<NodeNumber>,
    },
    /// Blobs arrived that the group's entries may wait for.
    Blobs,
}

/// What a group hears from its own leader loop, never dropped.
pub(crate) enum Local {
    /// A work result to replicate in `term`: its index, or why not.
    Propose {
        term: u64,
        payload: Vec<u8>,
        answer: smol::channel::Sender<Result<u64, ProposeError>>,
    },
    /// This replica's leader loop stopped for good: it hands leadership
    /// over and never campaigns again, but goes on applying.
    Retire,
}

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
    pub stopped: bool,
}

pub(crate) struct Shared {
    pub agent: AgentId,
    pub record: CreationRecord,
    /// The agent's identity: its record's hash, which clients sign for.
    pub identity: [u8; 32],
    state: Mutex<State>,
    changed: event_listener::Event,
    /// Whether each recent work result took: accumulate advanced the
    /// agent's version with it, rather than skipping it or failing.
    outcomes: Mutex<VecDeque<(u64, bool)>>,
}

impl Shared {
    pub fn new(record: CreationRecord) -> Self {
        Self {
            agent: record.agent,
            identity: crate::identity(&record),
            record,
            state: Mutex::new(State {
                role: Role::Follower,
                term: 0,
                leader: None,
                leading_from: None,
                commit: 0,
                written: 0,
                applied: 0,
                recovered: 0,
                stopped: false,
            }),
            changed: event_listener::Event::new(),
            outcomes: Mutex::new(VecDeque::new()),
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
    last_index: u64,
    proposals: HashMap<u64, smol::channel::Sender<Result<u64, ProposeError>>>,
    next_token: u64,
    /// The blobs asked for last, and when.
    asked: Option<(Instant, Vec<[u8; 32]>)>,
    /// Which member to ask next.
    turn: usize,
    /// The leader loop stopped for good.
    retired: bool,
    /// The writer health last reported to the core.
    stalled: bool,
}

enum Event {
    Input(Input),
    Local(Local),
    Closed,
    Timer,
}

impl Driver {
    /// Recover the group from the store, as step 3.3c's contract says:
    /// the writer told what is applied, the log cut at a lost blob, stale
    /// epochs dropped, then the core.
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
        let mut config = RaftConfig::new(
            inner.number,
            shared.record.replicas.clone(),
            shared.identity,
        );
        config.election_timeout_ms = inner.election_timeout_ms;
        config.heartbeat_interval_ms = inner.heartbeat_ms;
        let core = Core::new(config, raft::recovered(rows), 0, rand_seed());
        shared.update(|state| {
            state.written = last_index;
            state.applied = applied;
            state.recovered = recovered;
        });
        Ok(Self {
            agent,
            core,
            start: Instant::now(),
            reports: EntryReports::default(),
            writes: VecDeque::new(),
            last_index,
            proposals: HashMap::new(),
            next_token: 0,
            asked: None,
            turn: 0,
            retired: false,
            stalled: false,
            inner,
            shared,
        })
    }

    fn now(&self) -> u64 {
        self.start.elapsed().as_millis() as u64
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
                let mut wake = self.start + Duration::from_millis(self.core.next_deadline());
                if let Some((asked, _)) = &self.asked {
                    wake = wake.min(*asked + BLOB_RETRY);
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
                    smol::Timer::at(wake).await;
                    Event::Timer
                })
                .await;
                let now = self.now();
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
                if !self.process().await {
                    break;
                }
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
            if let Local::Propose { answer, .. } = local {
                let _ = answer.try_send(Err(ProposeError::Stopped));
            }
        }
        for (_, answer) in self.proposals.drain() {
            let _ = answer.try_send(Err(ProposeError::Stopped));
        }
    }

    fn take(&mut self, input: Input) {
        match input {
            Input::Raft { from, message } => self.core.receive(from, message),
            Input::Blobs => self.report_ready(),
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
                    let _ = answer.try_send(Err(ProposeError::NotLeader));
                    return;
                }
                let token = self.next_token;
                self.next_token += 1;
                self.proposals.insert(token, answer);
                self.core.propose(token, payload);
            }
            Local::Retire => self.retired = true,
        }
    }

    /// Tell the core whether its writer is stalled, or the replica retired:
    /// either way it hands leadership over and does not campaign.
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
                    // The core asks again when it next needs them.
                    _ => tracing::warn!(agent = self.agent.0, "a log load failed"),
                }
            }
            Action::Committed { index } => self.shared.update(|state| state.commit = index),
            // The log is kept whole until snapshots stream (step 3.7).
            Action::CompactBound { .. } => {}
            Action::SendSnapshot { to, .. } => self.core.snapshot_failed(to),
            Action::Answer(Answer::Propose { token, result }) => {
                if let Some(answer) = self.proposals.remove(&token) {
                    let _ = answer.try_send(result);
                }
            }
            Action::Answer(_) => {}
            Action::Changed { term, role, leader } => {
                // Becoming leader, the core appended its term's no-op last.
                let leading_from =
                    (role == Role::Leader).then(|| self.core.status().last_log_index);
                self.shared.update(|state| {
                    state.role = role;
                    state.term = term;
                    state.leader = leader;
                    state.leading_from = leading_from;
                });
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

    /// Ask for the blobs the group's entries wait for: the leader first,
    /// then each other member in turn.
    fn fetch_blobs(&mut self) {
        let missing = self.reports.missing();
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
            .shared
            .record
            .replicas
            .iter()
            .copied()
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
        let index = state.applied + 1;
        match apply_one(&inner, &shared, index).await {
            Ok(()) => {
                shared.update(|state| state.applied = index);
                backoff = BACKOFF;
            }
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
    inner.storage.commit(changes).await.map_err(Fault::Storage)
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
fn programs<'a>(rows: impl Iterator<Item = &'a Vec<u8>>) -> BTreeSet<[u8; 32]> {
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
