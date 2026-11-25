//! The protocol core: one replica of one group, as a state machine without
//! I/O. The host feeds it events (messages, proposals, ticks, write
//! completions) and carries out the actions it returns: ordered writes,
//! messages, log loads, commit notifications and answers.
//!
//! It follows etcd's asynchronous storage writes: writes are ordered and
//! several may be in flight; each carries the messages that may leave only
//! once it is durable; durability comes back as the write's sequence number.
//!
//! What waits for its write, and what goes at once:
//!
//! - an answer at a term above the durable term waits for the write of that
//!   term; a vote grant waits for the write of the vote; a candidate's vote
//!   requests wait for the write of its term and its own vote, and it
//!   counts grants, and leads, only at a durable term. A replica that
//!   crashes before that write never asked anyone at that term, so no
//!   grant made at a term can meet a second campaign at it;
//! - pre-votes and their answers, rejections and heartbeat answers at the
//!   durable term, and a leader's appends go at once.
//!
//! Who a replica takes messages from ([`Core::receive`]):
//!
//! - the host authenticates the sender, and passes a group only the
//!   messages of nodes that may speak for it: on VOS, the nodes the
//!   agent's placement names, and those of the configuration before while
//!   it is uncommitted. The core cannot do that check: a replica that lags
//!   a membership change does not know the members it added, and one of
//!   them may lead;
//! - from a node outside the configuration it knows, the core takes
//!   appends (a leader it has not heard of yet may be one), and vote
//!   requests and pre-votes only while it hears no leader (a member it has
//!   not heard of may be the candidate the group needs). It ignores their
//!   answers, which nothing it asked needs, and with them the terms they
//!   name;
//! - from anyone, it refuses what no correct peer sends: a term with no
//!   successor (`u64::MAX`) or more than 2^32 past its own, a second leader
//!   of a term it follows or leads (or led),
//!   and an append that would replace an entry at or below its commit
//!   index. A refused message changes nothing and is answered with
//!   nothing, as if lost; [`Status::refused`] counts them.
//!
//! What a replica may claim and apply:
//!
//! - durability is (index, term): a write's report vouches for its last
//!   entry only if the log still holds that entry, so a late report of a
//!   write whose entries a truncation replaced vouches for nothing;
//! - `verified` is the highest index matched against the current term's
//!   leader. An acknowledgement claims min(durable, verified), computed when
//!   it is sent, and a follower applies up to min(leader's commit,
//!   verified). A leader sends each peer a commit index of at most that
//!   peer's acknowledged index.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

use crate::config::{Config, NodeId};
use crate::log_entry::LogEntry;
use crate::log_view::LogView;
use crate::message::Message;
use crate::random::Random;
use crate::role::Role;

mod durability;
mod election;
mod host;
mod membership;
mod replication;
mod types;

pub use membership::ActiveConfigRecord;
pub use types::{
    Action, Answer, ChangeMembershipError, Load, ProposeError, ReadIndexError, Recovered,
    SnapshotSwitch, Status, Write,
};

/// The most a message may raise a replica's term by: no correct group
/// moves that far past one of its replicas, and a sender that names a term
/// near the last there is can then burn the group's terms only this many
/// at a time.
const TERM_LEAP: u64 = 1 << 32;

// ── Internal state ─────────────────────────────────────────

/// An append or a snapshot on its way to a peer: the last index it
/// carries, and when the leader stops waiting for its acknowledgement.
#[derive(Debug, Clone, Copy)]
struct Sending {
    last: u64,
    deadline: u64,
}

/// What a leader tracks of one peer, a member of its configuration.
#[derive(Debug, Clone)]
struct Progress {
    /// The next index to send it.
    next: u64,
    /// The highest index it is known to hold.
    matched: u64,
    /// One append in flight.
    in_flight: Option<Sending>,
    /// A snapshot on its way: no appends until it acknowledges it.
    snapshotting: Option<Sending>,
    /// Waiting for entries the cache had to load.
    loading: bool,
    /// The latest round it has answered at this term.
    acked_round: u64,
    /// The commit index it was last sent.
    sent_commit: u64,
    /// The highest commit index it answered an append carrying.
    acked_commit: u64,
    /// When it last sent a message at this term, or this leadership
    /// began: a peer owed entries that stops answering answers for itself
    /// at check-quorum, however alive its node.
    answered: u64,
    /// Its node the host has not heard lately ([`Core::vouch`]): an idle
    /// leader sends it no heartbeats.
    silent: bool,
}

impl Progress {
    fn new(next: u64, now: u64) -> Self {
        Self {
            next,
            matched: 0,
            in_flight: None,
            snapshotting: None,
            loading: false,
            acked_round: 0,
            sent_commit: 0,
            acked_commit: 0,
            answered: now,
            silent: false,
        }
    }
}

#[derive(Debug, Clone)]
struct LeaderState<N: NodeId> {
    /// Each member other than this replica.
    peers: BTreeMap<N, Progress>,
    /// Heartbeat rounds at this term, numbered from 1.
    round: u64,
    /// Members heard from since the last check-quorum, kept apart from
    /// `peers`: a member removed and added again before the next
    /// check-quorum still counts as heard.
    recent: BTreeSet<N>,
    /// A leadership transfer in progress, and when it gives up.
    transfer: Option<(N, u64)>,
    check_quorum_due: u64,
    /// The index of this term's first entry: a read is served at no lower.
    no_op: u64,
}

impl<N: NodeId> LeaderState<N> {
    fn new(check_quorum_due: u64, no_op: u64) -> Self {
        Self {
            peers: BTreeMap::new(),
            round: 0,
            recent: BTreeSet::new(),
            transfer: None,
            check_quorum_due,
            no_op,
        }
    }

    /// The highest index `peer` is known to hold.
    fn matched(&self, peer: N) -> u64 {
        self.peers.get(&peer).map_or(0, |progress| progress.matched)
    }
}

#[derive(Debug, Clone)]
struct PendingRead {
    token: u64,
    required_index: u64,
    round: u64,
    deadline: Option<u64>,
}

/// An acknowledgement a follower owes once its claim is durable, at the
/// current term: a new term drops them all.
#[derive(Debug, Clone, Copy)]
struct PendingAck<N: NodeId> {
    leader: N,
    round: u64,
    commit: u64,
    upto: u64,
}

#[derive(Debug, Clone, Copy)]
struct PendingWrite<N: NodeId> {
    seq: u64,
    hard: Option<(u64, Option<N>)>,
}

/// The protocol core of one replica.
pub struct Core<N: NodeId> {
    cfg: Config<N>,
    role: Role,
    term: u64,
    vote: Option<N>,
    commit: u64,
    log: LogView<N>,

    durable_index: u64,
    /// Which write appended the entries above the durable index: runs of
    /// (first index, write), in index order and so in write order.
    written: VecDeque<(u64, u64)>,
    durable_term: u64,
    durable_vote: Option<N>,
    /// The highest index matched against the current term's leader.
    verified: u64,
    /// The highest applied index the host made durable.
    durably_applied: u64,

    now: u64,
    /// When the election timer fires; while leading, when the next
    /// heartbeat round is due (`u64::MAX` for none).
    election_deadline: u64,
    last_heard_leader: Option<u64>,
    votes: BTreeSet<N>,
    pre_candidate_misses: u32,
    /// What a leader tracks of its followers, while it leads.
    leading: Option<LeaderState<N>>,
    reads: Vec<PendingRead>,
    pending_acks: Vec<PendingAck<N>>,
    seen_leader: Option<N>,
    writer_stalled: bool,
    /// Handovers started since the writer stalled.
    stalled_handovers: u32,

    // Membership.
    /// The configuration in effect, with the index of its entry.
    active: ActiveConfigRecord<N>,
    /// The configuration in effect at the log's start, always with its
    /// index, when known: a host that compacted without keeping it leaves
    /// it unknown.
    log_start_config: Option<ActiveConfigRecord<N>>,
    pending_joint_entry: Option<u64>,
    /// The last log position held before a wipe: see
    /// [`Recovered::vote_floor`].
    vote_floor: Option<(u64, u64)>,

    open: Option<Write<N>>,
    next_seq: u64,
    /// The write carrying the current term, while it is not durable.
    term_seq: u64,
    writes: VecDeque<PendingWrite<N>>,
    releases: Vec<(u64, N, Message<N>)>,
    loads: BTreeSet<(u64, u64)>,
    compact_bound: u64,
    rng: Random,
    actions: Vec<Action<N>>,
    announced: Option<(u64, Role, Option<N>)>,
    refused: u64,
    /// The last term this replica led: no other node leads it, after it
    /// steps down too.
    led: Option<u64>,
}

impl<N: NodeId> Core<N> {
    /// A replica recovered from its store, at time `now` (milliseconds on
    /// the host's monotonic clock), with a seed for its election jitter.
    /// The recovered entries continue the log from the snapshot's index
    /// on, without a gap; a member named twice in `cfg` counts once.
    pub fn new(mut cfg: Config<N>, recovered: Recovered<N>, now: u64, seed: u64) -> Self {
        let mut seen = BTreeSet::new();
        cfg.members.retain(|&member| seen.insert(member));
        let meta = recovered.meta;
        let mut log = LogView::new(
            meta.snap_last_index,
            meta.snap_last_term,
            cfg.cache_bytes,
            cfg.payload_weight,
        );
        let live: Vec<LogEntry<N>> = recovered
            .entries
            .into_iter()
            .filter(|entry| entry.index > meta.snap_last_index)
            .collect();
        log.append(&live);
        log.evict(log.last_index() + 1);
        let commit = meta
            .commit_index
            .max(recovered.applied)
            .min(log.last_index());
        // Hosts that keep the log start's configuration say it; otherwise a
        // persisted view at or below the log's start serves, and an empty
        // log starts with the static members. A record without its index
        // counts from the beginning.
        let snap = meta.snap_last_index;
        let static_config = ActiveConfigRecord::steady(0, cfg.members.clone());
        let log_start_config = recovered
            .log_start_config
            .or_else(|| {
                recovered
                    .active_config
                    .clone()
                    .filter(|record| record.log_index.is_some_and(|index| index <= snap))
            })
            .map(|record| ActiveConfigRecord {
                log_index: Some(record.log_index.unwrap_or(0)),
                ..record
            })
            .or_else(|| (snap == 0).then(|| static_config.clone()));
        let mut core = Self {
            active: static_config,
            log_start_config,
            cfg,
            role: Role::Follower,
            term: meta.current_term,
            vote: meta.voted_for,
            commit,
            durable_index: log.last_index(),
            written: VecDeque::new(),
            durable_term: meta.current_term,
            durable_vote: meta.voted_for,
            verified: commit,
            durably_applied: recovered.applied,
            log,
            now,
            election_deadline: now,
            last_heard_leader: None,
            votes: BTreeSet::new(),
            pre_candidate_misses: 0,
            leading: None,
            reads: Vec::new(),
            pending_acks: Vec::new(),
            seen_leader: None,
            writer_stalled: false,
            stalled_handovers: 0,
            pending_joint_entry: None,
            vote_floor: recovered.vote_floor,
            open: None,
            next_seq: 1,
            term_seq: 0,
            writes: VecDeque::new(),
            releases: Vec::new(),
            loads: BTreeSet::new(),
            compact_bound: meta.snap_last_index,
            rng: Random::new(seed),
            actions: Vec::new(),
            announced: None,
            refused: 0,
            led: None,
        };
        // A record recovery does not adopt (its entry is gone, or a newer
        // one is live) is written again, so no later restart brings it
        // back.
        let persisted = recovered.active_config.clone();
        core.recover_configuration(recovered.active_config);
        if persisted.is_some_and(|record| record != core.active) {
            core.write_active_config();
        }
        core.reset_election_timer();
        // No other member could lead: a lone member elects itself at its
        // first tick, without waiting out a timeout.
        if core.is_solo() && core.is_member() {
            core.election_deadline = now;
        }
        if core.commit > meta.commit_index {
            core.actions.push(Action::Committed { index: core.commit });
        }
        core
    }

    /// Time passes: `now` is the host's monotonic clock in milliseconds.
    pub fn tick(&mut self, now: u64) {
        self.now = self.now.max(now);
        // Reads time out on the clock; they resolve only on answers and
        // writes.
        self.answer_reads(None);
        if self.role == Role::Leader {
            self.leader_timers();
        }
        if self.cfg.check_quorum
            && self
                .leading
                .as_ref()
                .is_some_and(|leading| self.now >= leading.check_quorum_due)
        {
            self.check_quorum();
        }
        if self.now >= self.election_deadline {
            self.on_timer();
        }
    }

    /// Whether it is campaigning: a pre-candidate or a candidate.
    pub fn campaigning(&self) -> bool {
        matches!(self.role, Role::PreCandidate | Role::Candidate)
    }

    /// When the core next needs a tick.
    pub fn next_deadline(&self) -> u64 {
        let mut deadline = self.election_deadline;
        for read in &self.reads {
            if let Some(at) = read.deadline {
                deadline = deadline.min(at);
            }
        }
        if let Some(leading) = &self.leading {
            for progress in leading.peers.values() {
                for sending in progress.in_flight.iter().chain(&progress.snapshotting) {
                    deadline = deadline.min(sending.deadline);
                }
            }
            if let Some((_, at)) = leading.transfer {
                deadline = deadline.min(at);
            }
            if self.cfg.check_quorum && !self.is_solo() {
                deadline = deadline.min(leading.check_quorum_due);
            }
        }
        deadline
    }

    /// A message from `from`, already authenticated by the host; the
    /// module's doc says what the core takes, and from whom.
    pub fn receive(&mut self, from: N, message: Message<N>) {
        if !self.takes(from, &message) {
            self.refused += 1;
            return;
        }
        if let Some(leading) = self.leading.as_mut()
            && message.term() == self.term
            && self.active.contains(from)
        {
            leading.recent.insert(from);
            if let Some(progress) = leading.peers.get_mut(&from) {
                progress.answered = self.now;
            }
        }
        match message {
            append @ Message::Append { .. } => self.on_append(from, append),
            Message::AppendAnswer {
                term,
                round,
                commit,
                result,
            } => self.on_append_answer(from, term, round, commit, result),
            Message::Vote {
                term,
                candidate,
                last_index,
                last_term,
            } => self.on_vote(from, term, candidate, last_index, last_term),
            Message::VoteAnswer { term, granted } => self.on_vote_answer(from, term, granted),
            Message::PreVote {
                next_term,
                candidate,
                last_index,
                last_term,
            } => self.on_pre_vote(from, next_term, candidate, last_index, last_term),
            Message::PreVoteAnswer {
                term,
                next_term,
                granted,
            } => self.on_pre_vote_answer(from, term, next_term, granted),
            Message::TimeoutNow { term } => self.on_timeout_now(from, term),
        }
    }

    /// Whether to take `message` from `from` at all, as the module's doc
    /// says, and a `TimeoutNow` from outside the configuration, which
    /// counts only from the leader followed. A leader tracks its
    /// configuration's members only, so a late answer from a replica a
    /// change removed draws nothing.
    fn takes(&self, from: N, message: &Message<N>) -> bool {
        let named = match message {
            Message::PreVote { next_term, .. } => *next_term,
            message => message.term(),
        };
        if named == u64::MAX || named > self.term.saturating_add(TERM_LEAP) {
            return false;
        }
        if self.active.contains(from) {
            return true;
        }
        match message {
            Message::Append { .. } | Message::TimeoutNow { .. } => true,
            Message::Vote { .. } | Message::PreVote { .. } => !self.hears_a_leader(),
            Message::AppendAnswer { .. }
            | Message::VoteAnswer { .. }
            | Message::PreVoteAnswer { .. } => false,
        }
    }

    /// Whether the leader was last heard more than `margin` before the
    /// election timeout's lower end.
    pub(super) fn leader_heard_within(&self, margin: u64) -> bool {
        let low = self.cfg.election_timeout_ms.0;
        self.last_heard_leader
            .is_some_and(|heard| heard + low > self.now + margin)
    }

    /// Whether this replica leads, or heard its leader within the election
    /// timeout's lower end.
    fn hears_a_leader(&self) -> bool {
        let low = self.cfg.election_timeout_ms.0;
        self.role == Role::Leader
            || (self.seen_leader.is_some()
                && self
                    .last_heard_leader
                    .is_some_and(|heard| self.now < heard.saturating_add(low)))
    }

    /// Append `payload` to the log; answered with its index.
    pub fn propose(&mut self, token: u64, payload: Vec<u8>) {
        if self.role != Role::Leader || self.transferring() {
            self.answer(Answer::Propose {
                token,
                result: Err(ProposeError::NotLeader),
            });
            return;
        }
        let index = self.log.last_index() + 1;
        self.write_entries(alloc::vec![LogEntry::data(index, self.term, payload)]);
        self.answer(Answer::Propose {
            token,
            result: Ok(index),
        });
        self.replicate_all();
    }

    /// A linearizable read: answered with an index the reader must apply
    /// through before reading.
    pub fn read_index(&mut self, token: u64, timeout_ms: Option<u64>) {
        let Some(leading) = &self.leading else {
            self.answer(Answer::ReadIndex {
                token,
                result: Err(ReadIndexError::NotLeader),
            });
            return;
        };
        // A read is served at an index no lower than this term's no-op, so it
        // never sees state a later leader could revert.
        let (round, required_index) = (leading.round + 1, self.commit.max(leading.no_op));
        if self.reads.len() >= self.cfg.max_pending_reads {
            self.answer(Answer::ReadIndex {
                token,
                result: Err(ReadIndexError::Backpressure),
            });
            return;
        }
        self.reads.push(PendingRead {
            token,
            required_index,
            round,
            deadline: timeout_ms.map(|timeout| self.now.saturating_add(timeout)),
        });
        if self.is_solo() {
            self.try_resolve_reads();
        } else {
            self.send_heartbeats();
        }
    }

    /// Start a membership change to `members` (joint consensus), each
    /// named once.
    pub fn change_membership(&mut self, token: u64, members: Vec<N>) {
        let result = self.start_membership_change(members);
        self.answer(Answer::ChangeMembership { token, result });
    }

    /// The host made its writes through `seq` durable: their terms, votes
    /// and truncations. Their entries count once reported with
    /// [`Self::entries_durable`], which a host may delay (until the blobs
    /// an entry names are durable too) without holding back a term or a
    /// vote.
    pub fn durable(&mut self, seq: u64) {
        while self.writes.front().is_some_and(|write| write.seq <= seq) {
            let write = self.writes.pop_front().expect("checked above");
            if let Some((term, vote)) = write.hard
                && term >= self.durable_term
            {
                self.durable_term = term;
                self.durable_vote = vote;
            }
        }
        let released: Vec<_> = self
            .releases
            .extract_if(.., |&mut (at, ..)| at <= seq)
            .collect();
        for (_, to, message) in released {
            self.send(to, message);
        }
        if self.role == Role::Candidate
            && self.durable_term == self.term
            && self.durable_vote == Some(self.cfg.me)
            && self.votes.insert(self.cfg.me)
        {
            self.check_election();
        }
        self.flush_acks();
        self.leader_progress();
    }

    /// What a leader does once more of its log or a peer's is durable.
    fn leader_progress(&mut self) {
        if self.role == Role::Leader {
            self.try_advance_commit();
            self.try_resolve_reads();
            self.maybe_send_timeout_now();
        }
    }

    /// The host holds the entries of every write through `seq` durably,
    /// with every blob each names. It counts only for entries those writes
    /// appended that the log still holds: an entry written again since, by
    /// a later write, waits for that write's report.
    pub fn entries_durable(&mut self, seq: u64) {
        let bound = self
            .written
            .iter()
            .find(|&&(_, write)| write > seq)
            .map_or(self.log.last_index(), |&(first, _)| first - 1);
        if bound <= self.durable_index {
            return;
        }
        self.durable_index = bound;
        self.forget_written();
        self.flush_acks();
        self.leader_progress();
    }

    /// The host cannot complete the entries it never reported durable (a
    /// blob one names is lost): the replica drops those above its durable
    /// and commit indexes, as a crash would drop unsynced writes. It never
    /// acknowledged them, and an entry committed is held, with its blobs,
    /// by a quorum it can fetch them from. A candidate or a leader steps
    /// down first: its requests advertised the longer log, so no grant
    /// made against it may still count, and a leader counts only a quorum,
    /// so what it committed is kept. A configuration entry dropped drops
    /// its configuration, as a truncation by a leader does.
    pub fn discard_unreported(&mut self) {
        let keep = self.durable_index.max(self.commit);
        if self.log.last_index() <= keep {
            return;
        }
        if self.role != Role::Follower {
            self.step_down();
        }
        self.write_truncate(keep);
        self.follow_membership(Some(keep), &[]);
        self.verified = self.verified.min(keep);
    }

    /// Streaming a snapshot to `to` failed; it goes back to probing.
    pub fn snapshot_failed(&mut self, to: N) {
        if let Some(leading) = self.leading.as_mut()
            && let Some(progress) = leading.peers.get_mut(&to)
        {
            progress.snapshotting = None;
        }
    }

    /// The host made its applies through `index` durable.
    pub fn durably_applied(&mut self, index: u64) {
        self.durably_applied = self.durably_applied.max(index);
        self.update_compact_bound();
    }

    /// The writer stalled, or recovered. A replica whose writer is stalled
    /// hands over its leadership and does not campaign.
    pub fn writer_health(&mut self, stalled: bool) {
        self.writer_stalled = stalled;
        if !stalled {
            self.stalled_handovers = 0;
        }
        if stalled && self.role == Role::Leader {
            self.transfer_leadership(None);
        }
    }

    /// The actions since the last call, in order.
    pub fn take_actions(&mut self) -> Vec<Action<N>> {
        self.close_write();
        // An idle leader's heartbeats start again once a follower is not
        // caught up: entries or a commit it has not acknowledged, an
        // append or a snapshot that failed.
        if self.role == Role::Leader && self.election_deadline == u64::MAX {
            let me = self.cfg.me;
            if self.active.others(me).any(|peer| !self.caught_up(peer)) {
                self.election_deadline = self.now + self.cfg.heartbeat_interval_ms;
            }
        }
        let state = (self.term, self.role, self.seen_leader);
        if self.announced != Some(state) {
            self.announced = Some(state);
            self.actions.push(Action::Changed {
                term: self.term,
                role: self.role,
                leader: self.seen_leader,
            });
        }
        core::mem::take(&mut self.actions)
    }

    /// Bytes of recent entries the core holds in memory
    /// ([`Config::cache_bytes`] bounds them).
    pub fn cached_bytes(&self) -> usize {
        self.log.cached_bytes()
    }

    pub fn role(&self) -> Role {
        self.role
    }

    /// The highest index `peer` is known to hold, while this replica
    /// leads.
    pub fn match_index(&self, peer: N) -> Option<u64> {
        let progress = self.leading.as_ref()?.peers.get(&peer)?;
        Some(progress.matched)
    }

    pub fn status(&self) -> Status<N> {
        Status {
            role: self.role,
            current_term: self.term,
            voted_for: self.vote,
            last_log_index: self.log.last_index(),
            commit_index: self.commit,
            snap_last_index: self.log.snap_index(),
            durable_index: self.durable_index,
            members: self.active.current.clone(),
            joint_old: self.active.joint_old.clone(),
            active_config_index: self.active.log_index,
            leader_hint: self.seen_leader,
            refused: self.refused,
        }
    }
}
