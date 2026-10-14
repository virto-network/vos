//! A group's driver: its consensus core, fed by the network, the leader
//! loop and the node's log writer, and the work its actions ask for.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::sync::atomic::Ordering;
use std::sync::{Arc, PoisonError};
use std::time::{Duration, Instant};

use smol::future::FutureExt;
use vos_net::Class;
use vos_raft::core::{
    Action, Answer, ChangeMembershipError, Core, ProposeError, ReadIndexError, Write,
};
use vos_raft::{Config as RaftConfig, Role};
use vos_wire::Encode;
use vos_wire::peer::{NodeNumber, PeerMessage, Placement};

use super::snapshot::{INSTALL_IDLE, STREAM_HOLD};
use super::{Driver, Input, Local, Shared};
use crate::node::Inner;
use crate::raft::{self, EntryReports};
use crate::random_u64;
use crate::storage::Change;

/// How long a group waits for blobs it asked for before asking again,
/// another member.
const BLOB_RETRY: Duration = Duration::from_secs(1);
/// Inputs a driver takes in one round, so the core joins them in one
/// write.
const ROUND: usize = 1024;

/// How long a read index may wait for a quorum to confirm the leader.
const READ_INDEX_MS: u64 = 2_000;

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
        config.snapshot_timeout_ms = settings.snapshot_timeout_ms;
        // The pair heartbeat vouches for an idle group's leader. An idle
        // leader goes round once per check-quorum window, which keeps it
        // listed.
        config.idle_heartbeats = false;
        config.check_quorum = true;
        let core = Core::new(config, raft::recovered(rows), 0, random_u64());
        let established = established(&core, inner.number);
        shared.update(|state| {
            state.written = last_index;
            state.applied = applied;
            state.recovered = recovered;
            state.established = established;
        });
        Ok(Self {
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
            handing_over: false,
            shipments: HashMap::new(),
            install: None,
            install_missing: Vec::new(),
            chunks: VecDeque::new(),
            compact_bound: 0,
            compact_due: false,
            memberships: HashMap::new(),
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
        let table = self
            .inner
            .liveness
            .table
            .read()
            .unwrap_or_else(PoisonError::into_inner);
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
        if self.process().await {
            loop {
                if self.shared.state().stopped {
                    break;
                }
                self.shared
                    .woke
                    .store(self.inner.liveness.elapsed(), Ordering::Relaxed);
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
                for staged in self
                    .shipments
                    .values()
                    .filter_map(|shipment| shipment.staged)
                {
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
                    .durably_applied(self.inner.storage.durably_applied(self.shared.agent));
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
                Local::Retire | Local::StreamEnded { .. } | Local::Probe(_) | Local::Wake => {}
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
                if let Some(shipment) = self.shipments.get(&from)
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
                let Some(shipment) = self
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
                    self.shipments.remove(&to);
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
        let handing_over = self.retired || self.inner.storage.stalled();
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
            Action::Send { to, message } => {
                if let Some(network) = &self.inner.network {
                    let frame = PeerMessage::Raft {
                        agent: self.shared.agent,
                        message: crate::peer::to_wire(&message),
                    }
                    .encode();
                    // Refused, it is dropped: Raft sends again.
                    let _ =
                        network.send(to, Class::Consensus, u64::from(self.shared.agent.0), frame);
                }
            }
            Action::LoadEntries(load) => {
                let store = self.inner.store.clone();
                let agent = self.shared.agent;
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
                    self.shipments.clear();
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
                        self.announce_placement().await;
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
                    tracing::warn!(agent = self.shared.agent.0, "a blob touch failed: {error}");
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
        // log's first, which may be this one. It matters while a placement
        // is uncommitted, and names a leader the change removed, which
        // leads until the configuration without it commits.
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
        if self.announced == Some(order) {
            return;
        }
        self.announced = Some(order);
        let inner = Arc::clone(&self.inner);
        let agent = self.shared.agent;
        self.inner
            .spawn(async move { inner.place(agent, placement).await });
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
        let retry = self
            .asked
            .as_ref()
            .is_some_and(|(at, _)| at.elapsed() >= BLOB_RETRY);
        let fresh = self
            .asked
            .as_ref()
            .is_none_or(|(_, asked)| missing.iter().any(|hash| !asked.contains(hash)));
        if !retry && !fresh {
            return;
        }
        let Some(network) = &self.inner.network else {
            return;
        };
        let me = self.inner.number;
        let others: Vec<NodeNumber> = self
            .inner
            .placement(self.shared.agent)
            .map(|placement| placement.replicas)
            .unwrap_or_default()
            .into_iter()
            .filter(|node| *node != me)
            .collect();
        if others.is_empty() {
            return;
        }
        // Blobs not asked for yet go to the leader, which stored any large
        // result it proposed; a retry turns to the next member.
        let leader = self.shared.state().leader.filter(|leader| *leader != me);
        let target = match leader {
            Some(leader) if !retry => leader,
            _ => {
                self.turn += 1;
                others[self.turn % others.len()]
            }
        };
        // Retries keep their pace while new blobs join the ask.
        let since = match &self.asked {
            Some((at, _)) if !retry => *at,
            _ => Instant::now(),
        };
        self.inner.want(self.shared.agent, &missing);
        let frame = PeerMessage::BlobRequest {
            agent: self.shared.agent,
            hashes: missing.clone(),
        }
        .encode();
        let _ = network.send(
            target,
            Class::Requests,
            u64::from(self.shared.agent.0),
            frame,
        );
        self.asked = Some((since, missing));
    }
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
