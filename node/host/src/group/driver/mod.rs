//! A group's driver: its consensus core, fed by the network, the leader
//! loop and the node's log writer, and the work its actions ask for.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vos_raft::core::{
    Action, Answer, ChangeMembershipError, Core, ProposeError, ReadIndexError, Write,
};
use vos_raft::{Config as RaftConfig, Role};
use vos_wire::peer::{NodeNumber, Order, PeerMessage};

mod fetch;
mod membership;
mod snapshot;

use super::{Input, Local, MembershipChanged, Proposed, Quiet, ReadIndexed, Shared};
use crate::blobs::Held;
use crate::node::Inner;
use crate::raft::{self, EntryReports};
use crate::storage::Change;
use crate::{lock, random};
use fetch::Fetch;
use membership::established;
use snapshot::{INSTALL_IDLE, STREAM_HOLD, Snapshots};

/// Inputs a driver takes in one round, so the core joins them in one
/// write.
const ROUND: usize = 1024;

/// How long a read index may wait for a quorum to confirm the leader.
const READ_INDEX_MS: u64 = 2_000;

/// A quiet group's driver still goes round once every this many of the
/// election timeout's upper end: should the pair heartbeat's thread fail
/// to wake it, its own timers take over then.
const QUIET_ROUNDS: u32 = 10;

enum Event {
    Input(Input),
    Local(Local),
    Closed,
    Timer,
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
    core: Core<NodeNumber>,
    start: Instant,
    reports: EntryReports,
    /// Each write not yet reported with its blobs, by sequence, with the
    /// log's last index after it.
    writes: VecDeque<(u64, u64)>,
    /// The log's last index as written to the store.
    /// [`super::State::written`] reaches it only once the entries' blobs
    /// are stored too.
    last_index: u64,
    answers: Answers,
    fetch: Fetch,
    /// The held blobs of proposals not yet answered, by token.
    held_proposals: HashMap<u64, Held>,
    /// The held blobs of entries not yet written, by index: released once
    /// a write reaches it, or truncates it.
    held_entries: Vec<(u64, Held)>,
    /// The leader loop stopped for good.
    retired: bool,
    /// The core was last told to hand leadership over and not campaign.
    handing_over: bool,
    snapshots: Snapshots,
    /// The highest compaction bound the core gave.
    compact_bound: u64,
    /// A compaction is due at the next chance.
    compact_due: bool,
    /// The order of the placement this replica last announced as leader,
    /// since it last stepped down: set as it goes to the directory, in a
    /// task of its own, as the driver never waits on the node-wide lock a
    /// placement takes.
    announced: Option<Order>,
}

/// Where the core's answers go, by the token each request took.
#[derive(Default)]
struct Answers {
    proposals: HashMap<u64, Proposed>,
    reads: HashMap<u64, ReadIndexed>,
    memberships: HashMap<u64, MembershipChanged>,
    next_token: u64,
}

impl Answers {
    /// A token no request took.
    fn token(&mut self) -> u64 {
        let token = self.next_token;
        self.next_token += 1;
        token
    }

    /// Answer every request waiting that the group stopped.
    fn stop(&mut self) {
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
}

impl Driver {
    /// Recover the group from the store, in order: the writer told what is
    /// applied, the log cut at a lost blob, stale epochs dropped, then the
    /// core. A committed entry whose blob was lost stays, and waits for it
    /// as a fresh append would.
    pub(super) async fn start(inner: Arc<Inner>, shared: Arc<Shared>) -> Result<Self, String> {
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
        // The members it was created with, the log's first configuration,
        // used until its store holds another: a replica added later is none
        // of them, so it never campaigns until the configuration naming it
        // reaches it.
        let members = shared.record.replicas.clone();
        let mut config = RaftConfig::new(inner.number, members);
        let settings = &inner.settings;
        config.election_timeout_ms = settings.election_timeout_ms;
        config.heartbeat_interval_ms = settings.heartbeat_ms;
        config.compact_hysteresis = settings.compact_every;
        config.compact_bytes = settings.compact_bytes;
        config.payload_weight = raft::payload_weight;
        config.snapshot_timeout_ms = settings.snapshot_timeout_ms;
        // The pair heartbeat vouches for an idle group's leader. An idle
        // leader goes round once per check-quorum window, which keeps it
        // listed.
        config.idle_heartbeats = false;
        config.check_quorum = true;
        let core = Core::new(
            config,
            raft::recovered(rows),
            0,
            u64::from_le_bytes(random()),
        );
        let established = established(&core, inner.number);
        // The core counts every recovered entry durable, which a committed
        // one is safe to be: nothing applies past a lost blob until a
        // member sends it, or the leader's log compacts past this one's and
        // a snapshot comes.
        let mut reports = EntryReports::default();
        let mut writes = VecDeque::new();
        let mut written = last_index;
        if let Some(&(first, _)) = cut.refetch.first() {
            tracing::error!(
                agent = agent.0,
                index = first,
                "the store lost the blobs of committed entries from {first}: this replica fetches \
                 them again, and applies nothing from {first} on, nor leads, until they come"
            );
            written = first - 1;
            writes.push_back((raft::RECOVERED, last_index));
            reports.recovered(cut.refetch);
        }
        shared.update(|state| {
            state.written = written;
            state.applied = applied;
            state.recovered = recovered;
            state.established = established;
        });
        Ok(Self {
            core,
            start: Instant::now(),
            reports,
            writes,
            last_index,
            answers: Answers::default(),
            fetch: Fetch::default(),
            held_proposals: HashMap::new(),
            held_entries: Vec::new(),
            retired: false,
            handing_over: false,
            snapshots: Snapshots::default(),
            compact_bound: 0,
            compact_due: false,
            announced: None,
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
        let agent = self.shared.agent;
        let table = self.inner.liveness.table();
        self.core.vouch(
            now,
            |node, term| table.listed(node, &agent, term).map(at),
            |node| table.heard_at(node).map(at),
        );
    }

    pub(super) async fn run(
        mut self,
        inbox: smol::channel::Receiver<Input>,
        local: smol::channel::Receiver<Local>,
    ) {
        // Before the first tick, so a replica whose recovered entries wait
        // for their blobs never campaigns.
        self.report_health();
        if self.process().await {
            // Blobs recovery found lost are asked for at once.
            self.fetch_blobs();
            loop {
                if self.shared.state().stopped {
                    break;
                }
                self.shared
                    .woke
                    .store(self.inner.liveness.elapsed(), Ordering::Relaxed);
                self.shared
                    .log_cache
                    .store(self.core.cached_bytes() as u64, Ordering::Relaxed);
                // What the driver waits for besides the core.
                let mut other: Option<Instant> = None;
                let mut sooner = |at: Instant| {
                    other = Some(other.map_or(at, |other| other.min(at)));
                };
                if let Some(due) = self.fetch.due() {
                    sooner(due);
                }
                if let Some(install) = &self.snapshots.install {
                    sooner(install.since + INSTALL_IDLE);
                }
                for staged in self
                    .snapshots
                    .shipments
                    .values()
                    .filter_map(|shipment| shipment.staged)
                {
                    sooner(staged + STREAM_HOLD);
                }
                // A quiet core's timers are the pair heartbeat's to stand
                // in for: the driver sleeps until a message, a local, the
                // pair heartbeat's wake, or its long round.
                let quiet = other.is_none().then(|| self.quiet()).flatten();
                let quiesced = quiet.is_some();
                *lock(&self.shared.quiet) = quiet;
                let wake = if quiesced {
                    let round = Duration::from_millis(self.inner.settings.election_timeout_ms.1);
                    Some(Instant::now() + round * QUIET_ROUNDS)
                } else {
                    // An idle core may need no tick at all.
                    let core = self
                        .start
                        .checked_add(Duration::from_millis(self.core.next_deadline()));
                    match (core, other) {
                        (Some(core), Some(other)) => Some(core.min(other)),
                        (core, other) => core.or(other),
                    }
                };
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
                if quiesced {
                    *lock(&self.shared.quiet) = None;
                    self.shared
                        .woke
                        .store(self.inner.liveness.elapsed(), Ordering::Relaxed);
                }
                let now = self.now();
                if quiesced {
                    self.core.resume(now);
                }
                // A deadline due runs only once the pair heartbeat had its
                // say, as does a round after a quiet wait, whose timers it
                // stood in for.
                if quiesced || self.core.next_deadline() <= now {
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
                    .durably_applied(self.inner.storage.durably_applied(self.shared.agent));
                self.settle_streams();
                if !self.process().await || !self.stage().await {
                    break;
                }
                self.compact().await;
                if !self.process().await {
                    break;
                }
                self.settle_membership();
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
            local.refuse_stopped();
        }
        self.answers.stop();
    }

    /// Why the driver may wait on no timer of its own now, if it may: the
    /// core needs no tick but those the pair heartbeat stands in for, which
    /// notices a lapse within a round of it.
    fn quiet(&self) -> Option<Quiet> {
        let every = self.inner.settings.heartbeat_ms;
        if !self.inner.liveness.on_time(every) || !self.core.quiescent(every) {
            return None;
        }
        let status = self.core.status();
        match status.role {
            Role::Follower => Some(Quiet::Following {
                leader: status.leader_hint?,
                term: status.current_term,
            }),
            Role::Leader => {
                let me = self.inner.number;
                let mut members: Vec<NodeNumber> = status
                    .members
                    .iter()
                    .chain(status.joint_old.iter().flatten())
                    .copied()
                    .filter(|&member| member != me)
                    .collect();
                members.sort_unstable();
                members.dedup();
                Some(Quiet::Leading { members })
            }
            Role::PreCandidate | Role::Candidate => None,
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
            Input::Chunk { from, chunk } => self.snapshots.chunks.push_back((from, chunk)),
            Input::ChunkAck { from, ack } => {
                if let Some(shipment) = self.snapshots.shipments.get(&from)
                    && (ack.agent, ack.term, ack.index)
                        == (self.shared.agent, shipment.term, shipment.index)
                {
                    let _ = shipment.acks.try_send(ack.next);
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
                held,
            } => {
                if self.core.role() != Role::Leader || self.core.status().current_term != term {
                    let _ = answer.try_send((Err(ProposeError::NotLeader), Instant::now()));
                    return;
                }
                let token = self.answers.token();
                self.answers.proposals.insert(token, answer);
                if let Some(held) = held {
                    self.held_proposals.insert(token, held);
                }
                self.core.propose(token, payload);
            }
            Local::Retire => self.retired = true,
            Local::Probe(node) => self.core.probe(node),
            Local::Wake => {}
            Local::Transfer(to) => self.core.transfer_leadership(Some(to)),
            Local::ReadIndex { answer } => {
                let token = self.answers.token();
                self.answers.reads.insert(token, answer);
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
                let token = self.answers.token();
                self.answers.memberships.insert(token, answer);
                self.core.change_membership(token, members);
            }
            Local::StreamEnded {
                to,
                term,
                index,
                done,
            } => {
                let Some(shipment) = self
                    .snapshots
                    .shipments
                    .get_mut(&to)
                    .filter(|shipment| (shipment.term, shipment.index) == (term, index))
                else {
                    return;
                };
                if done {
                    // Held until its follower switches: the log keeps the
                    // entries after it, and no other stream displaces it.
                    shipment.staged = Some(Instant::now());
                } else {
                    self.snapshots.shipments.remove(&to);
                    self.core.snapshot_failed(to);
                    self.compact_due = true;
                }
            }
        }
    }

    /// Tell the core whether to hand leadership over and not campaign, as
    /// it does while its writer is stalled. A replica whose leader loop
    /// stopped for good (`retired`) is reported as stalled on purpose.
    fn report_health(&mut self) {
        // A replica whose recovered entries wait for their blobs neither
        // campaigns nor leads: as leader it would wait on its own no-op
        // behind them, and hold up the group.
        let handing_over =
            self.retired || self.inner.storage.stalled() || self.reports.recovering();
        if handing_over != self.handing_over {
            self.handing_over = handing_over;
            self.core.writer_health(handing_over);
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
            // Refused, it is dropped: Raft sends again.
            Action::Send { to, message } => self.inner.send(
                to,
                &PeerMessage::Raft {
                    agent: self.shared.agent,
                    message: crate::peer::to_wire(&message),
                },
            ),
            Action::LoadEntries(load) => {
                let store = self.inner.store.clone();
                let agent = self.shared.agent;
                let loaded = self
                    .inner
                    .offload(move || raft::load(&store, agent, &load))
                    .await;
                match loaded {
                    Some(Ok(entries)) => self.core.loaded(load, entries),
                    // Nothing loaded: the core forgets the load, and asks
                    // again when its peers next answer.
                    _ => {
                        tracing::warn!(agent = self.shared.agent.0, "a log load failed");
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
                // A held blob stays held until its entry is written, and
                // touched: its row keeps it from then on.
                if let Some(held) = self.held_proposals.remove(&token)
                    && let Ok(index) = result
                    && index > self.last_index
                {
                    self.held_entries.push((index, held));
                }
                if let Some(answer) = self.answers.proposals.remove(&token) {
                    let _ = answer.try_send((result, Instant::now()));
                }
            }
            Action::Answer(Answer::ReadIndex { token, result }) => {
                if let Some(answer) = self.answers.reads.remove(&token) {
                    let _ = answer.try_send(result);
                }
            }
            Action::Answer(Answer::ChangeMembership { token, result }) => {
                if let Some(answer) = self.answers.memberships.remove(&token) {
                    let _ = answer.try_send(result);
                }
            }
            Action::Changed { term, role, leader } => {
                // A leadership's streams end with it.
                if role != Role::Leader {
                    self.snapshots.shipments.clear();
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
                    let removed = self.announced.is_some()
                        && status.joint_old.is_none()
                        && !status.members.contains(&me)
                        && status.commit_index >= status.active_config_index.unwrap_or(0);
                    if removed {
                        self.announce_placement();
                    }
                    self.announced = None;
                    // It retires once it steps down; a group stopping does
                    // not.
                    if !self.shared.state().stopped {
                        self.inner.reconsider(self.shared.agent);
                    }
                }
            }
        }
        true
    }

    async fn write(&mut self, write: Write<NodeNumber>) -> bool {
        let changes = raft::changes(self.shared.agent, &write);
        let named = raft::named(&changes);
        if let Err(error) = self.inner.storage.commit(changes).await {
            tracing::error!(
                agent = self.shared.agent.0,
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
        let hashes: Vec<[u8; 32]> = named
            .iter()
            .flat_map(|(_, hashes)| hashes.iter().copied())
            .collect();
        let stored: BTreeSet<[u8; 32]> = if hashes.is_empty() {
            BTreeSet::new()
        } else {
            // Touched, a blob stays while an entry comes to rely on it.
            match self.inner.blobs.touch(hashes).await {
                Ok(stored) => stored.into_iter().collect(),
                Err(error) => {
                    tracing::warn!(agent = self.shared.agent.0, "a blob touch failed: {error}");
                    BTreeSet::new()
                }
            }
        };
        self.reports
            .written(&write, named, |hash| stored.contains(hash));
        // A held blob's entry is written and touched now, or gone in this
        // write's truncation.
        let truncated = write.truncate_after;
        self.held_entries.retain(|(index, _)| {
            *index > self.last_index && truncated.is_none_or(|after| *index <= after)
        });
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
        // The recovered log's entries the core counted durable already.
        if seq != raft::RECOVERED {
            self.core.entries_durable(seq);
        }
        let mut written = None;
        while let Some(&(at, last)) = self.writes.front() {
            if at > seq {
                break;
            }
            if at == raft::RECOVERED {
                tracing::info!(
                    agent = self.shared.agent.0,
                    "the lost blobs of committed entries arrived"
                );
            }
            written = Some(last);
            self.writes.pop_front();
        }
        if let Some(written) = written {
            self.shared.update(|state| state.written = written);
        }
    }
}
