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

mod actions;
mod fetch;
mod membership;
mod snapshot;

use super::{Campaign, Input, Local, MembershipChanged, Proposed, Quiet, ReadIndexed, Shared};
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
    /// since it last stepped down: set as it goes to the directory's
    /// recording, which the driver never waits on.
    announced: Option<Order>,
    /// The node's campaign this replica holds while it campaigns.
    campaign: Option<Campaign>,
    /// It waits its turn for one.
    waiting: bool,
}

/// A driver gone, however it ended (a panic included), neither waits for
/// a campaign nor keeps one handed to it.
impl Drop for Driver {
    fn drop(&mut self) {
        self.inner.campaigns.forget(self.shared.agent);
    }
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
        let failed = |error: fjall::Error| error.to_string();
        // The store's reads run on an executor: a node starting many
        // groups at once keeps its runtime for those already started.
        let (store, blobs) = (inner.store.clone(), inner.blobs.clone());
        let (applied, cut, stale) = inner
            .offload(move || {
                let applied = store.raft(agent)?.applied;
                let cut = raft::recovery_cut(&store, &blobs, agent)?;
                Ok((applied, cut, store.stale_epochs(agent)?))
            })
            .await
            .ok_or("the executors stopped")?
            .map_err(failed)?;
        inner.storage.recovered(agent, applied);
        if !cut.changes.is_empty() {
            inner.storage.commit(cut.changes).await?;
        }
        for epoch in stale {
            inner
                .storage
                .commit(vec![Change::DropEpoch {
                    agent,
                    epoch,
                    limit: usize::MAX,
                }])
                .await?;
        }
        let store = inner.store.clone();
        let rows = inner
            .offload(move || store.raft(agent))
            .await
            .ok_or("the executors stopped")?
            .map_err(failed)?;
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
            campaign: None,
            waiting: false,
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
                // pair heartbeat's wake, or its long round. Set under the
                // peer table's lock, so a change to the listing it rests on
                // either comes before, and keeps it awake, or finds it
                // quiet, and wakes it.
                let quiesced = {
                    let table = self.inner.liveness.table();
                    let quiet = other.is_none().then(|| self.quiet(&table)).flatten();
                    let quiesced = quiet.is_some();
                    *lock(&self.shared.quiet) = quiet;
                    quiesced
                };
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
                // A campaign starts, or goes another round, only with one
                // of the node's campaigns: past their bound it waits its
                // turn, so a node that wakes many leaderless groups at once
                // elects them in turn rather than have them all time out
                // together, each woken as one ends. A round that did not
                // settle gives its campaign back and waits its turn again,
                // so groups that keep losing do not keep the others out.
                let due = self.core.campaign_due(now);
                if due {
                    self.campaign = None;
                }
                if (due || self.waiting) && self.campaign.is_none() {
                    let high = self.inner.settings.election_timeout_ms.1;
                    match self.inner.campaigns.take(self.shared.agent) {
                        Some(campaign) => {
                            self.campaign = Some(campaign);
                            if std::mem::take(&mut self.waiting) {
                                self.core.campaign_now(now);
                            }
                        }
                        // Woken in turn, or failing that after ten election
                        // timeouts.
                        None => {
                            self.waiting = true;
                            self.core
                                .defer_campaign(now, now + QUIET_ROUNDS as u64 * high);
                        }
                    }
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
                // A campaign ends as the replica leads or follows a leader.
                if !self.core.campaigning() {
                    self.campaign = None;
                }
            }
        }
        // A caller who sees the group gone sees it lead nothing, and a
        // proposal still queued hears so.
        self.inner.led_here(self.shared.agent, false);
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
    fn quiet(&self, table: &crate::liveness::Table) -> Option<Quiet> {
        let every = self.inner.settings.heartbeat_ms;
        if !self.inner.liveness.on_time(every) || !self.core.quiescent(every) {
            return None;
        }
        let status = self.core.status();
        match status.role {
            // Only while its leader's listing names it, fresh enough to
            // stand in for its timer until the next round: a change to that
            // listing then wakes it.
            Role::Follower => {
                let (leader, term) = (status.leader_hint?, status.current_term);
                let listed = table.listed(leader, &self.shared.agent, term)?;
                let (low, margin) = (self.inner.settings.election_timeout_ms.0, every);
                let fresh = listed + Duration::from_millis(low)
                    > Instant::now() + Duration::from_millis(margin);
                fresh.then_some(Quiet::Following { leader, term })
            }
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
}
