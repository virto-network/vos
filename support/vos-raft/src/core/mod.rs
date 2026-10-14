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
//!   term; a vote grant waits for the write of the vote; a candidate counts
//!   its own vote only once its term and vote are durable;
//! - pre-votes and their answers, rejections and heartbeat answers at the
//!   durable term, and a leader's appends go at once.
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
use crate::meta::Meta;
use crate::random::Random;
use crate::role::Role;

mod durability;
mod election;
mod membership;
mod replication;

pub use membership::ActiveConfigRecord;

/// Why a proposal was not appended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProposeError {
    /// This replica is not the leader, or is handing leadership over.
    NotLeader,
    /// The replica's host stopped it (its store failed, or it shut down).
    /// The core never returns it.
    Stopped,
}

/// Why a read index was not granted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReadIndexError {
    NotLeader,
    /// The leader stepped down before a quorum confirmed it.
    LeaderStepped,
    /// Too many reads are queued.
    Backpressure,
    /// The read's deadline passed first.
    TimedOut,
    /// The replica's host stopped it. The core never returns it.
    Stopped,
}

/// Why a membership change was not started.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ChangeMembershipError {
    NotLeader,
    /// Another change is still in progress.
    InProgress,
    EmptyConfig,
    /// The replica's host stopped it. The core never returns it.
    Stopped,
}

/// One ordered write. A host applies it atomically: truncate, then append,
/// then the meta and configuration rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Write<N: NodeId> {
    pub seq: u64,
    pub truncate_after: Option<u64>,
    pub entries: Vec<LogEntry<N>>,
    /// The hard state and commit index. Its snapshot pointer is the core's
    /// view when the write was made; the host keeps its own, which only
    /// compaction and a snapshot switch move.
    pub meta: Option<Meta<N>>,
    pub active_config: Option<ActiveConfigRecord<N>>,
    /// Whether the write must be synced before it counts: entries, terms and
    /// votes are; a commit-index move alone is not.
    pub sync: bool,
}

/// A request for log entries the core's cache no longer holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Load {
    pub from: u64,
    pub to: u64,
    /// The term the request was made in; older results are dropped.
    pub term: u64,
    /// The host may return a shorter prefix within this many bytes, but at
    /// least one entry.
    pub max_bytes: usize,
}

/// The answer to a request the host made with a token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    Propose {
        token: u64,
        result: Result<u64, ProposeError>,
    },
    ReadIndex {
        token: u64,
        result: Result<u64, ReadIndexError>,
    },
    ChangeMembership {
        token: u64,
        result: Result<u64, ChangeMembershipError>,
    },
}

/// What the host must do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action<N: NodeId> {
    Write(Write<N>),
    Send {
        to: N,
        message: Message<N>,
    },
    LoadEntries(Load),
    /// Entries through `index` may be applied.
    Committed {
        index: u64,
    },
    /// Stream this replica's state, as of the snapshot through `index`, to
    /// `to`, with the configuration it holds.
    SendSnapshot {
        to: N,
        index: u64,
        term: u64,
        configuration: Option<ActiveConfigRecord<N>>,
    },
    /// The log may be compacted through `through`. `configuration` is the
    /// one in effect there, when known, which the host keeps with the log's
    /// start: a later truncation that removes every configuration entry
    /// above it falls back to it.
    CompactBound {
        through: u64,
        configuration: Option<ActiveConfigRecord<N>>,
    },
    Answer(Answer),
    Changed {
        term: u64,
        role: Role,
        leader: Option<N>,
    },
}

/// The rows a host's snapshot switch writes in the same atomic batch as
/// the state: drop the log after `truncate_after` (when the log disagrees
/// at the snapshot's index), then the meta and the membership record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotSwitch<N: NodeId> {
    pub truncate_after: Option<u64>,
    pub meta: Meta<N>,
    pub active_config: ActiveConfigRecord<N>,
    /// The configuration in effect at the snapshot's index, when known,
    /// kept with the log's start.
    pub log_start_config: Option<ActiveConfigRecord<N>>,
}

/// What a replica recovers from its store.
#[derive(Debug, Clone)]
pub struct Recovered<N: NodeId> {
    pub meta: Meta<N>,
    /// The live log, from the snapshot boundary on.
    pub entries: Vec<LogEntry<N>>,
    pub active_config: Option<ActiveConfigRecord<N>>,
    /// The configuration in effect at the log's start, if the host kept it.
    pub log_start_config: Option<ActiveConfigRecord<N>>,
    /// The highest applied index recovered.
    pub applied: u64,
    /// The last log position (index, term) a replica held before its host
    /// wiped its log and state, keeping its term and vote: it votes only
    /// for candidates whose log reaches it, as if it still held that log.
    /// A host that wipes a replica a change removed keeps it, so the
    /// replica, added again empty, never votes for a removed one that
    /// never learned of its removal.
    pub vote_floor: Option<(u64, u64)>,
}

impl<N: NodeId> Default for Recovered<N> {
    fn default() -> Self {
        Self {
            meta: Meta::default(),
            entries: Vec::new(),
            active_config: None,
            log_start_config: None,
            applied: 0,
            vote_floor: None,
        }
    }
}

/// A diagnostic view of a replica.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Status<N: NodeId> {
    pub role: Role,
    pub current_term: u64,
    pub voted_for: Option<N>,
    pub last_log_index: u64,
    pub commit_index: u64,
    pub snap_last_index: u64,
    pub durable_index: u64,
    pub members: Vec<N>,
    pub joint_old: Option<Vec<N>>,
    pub active_config_index: Option<u64>,
    pub leader_hint: Option<N>,
}

// ── Internal state ─────────────────────────────────────────

#[derive(Debug, Clone, Copy)]
struct InFlight {
    last: u64,
    deadline: u64,
}

#[derive(Debug, Clone, Copy)]
struct Snapshotting {
    index: u64,
    deadline: u64,
}

#[derive(Debug, Clone)]
struct LeaderState<N: NodeId> {
    next_index: BTreeMap<N, u64>,
    match_index: BTreeMap<N, u64>,
    /// One append in flight per peer.
    in_flight: BTreeMap<N, InFlight>,
    /// Peers receiving a snapshot: no appends until they acknowledge it.
    snapshotting: BTreeMap<N, Snapshotting>,
    /// Peers waiting for entries the cache had to load.
    loading: BTreeSet<N>,
    /// Heartbeat rounds at this term, numbered from 1.
    round: u64,
    /// The latest round each peer has answered at this term.
    acked_round: BTreeMap<N, u64>,
    /// The commit index each peer was last sent.
    sent_commit: BTreeMap<N, u64>,
    /// The highest commit index each peer answered an append carrying.
    acked_commit: BTreeMap<N, u64>,
    /// When each peer last sent a message at this term, or this
    /// leadership began: a peer owed entries that stops answering answers
    /// for itself at check-quorum, however alive its node.
    answered: BTreeMap<N, u64>,
    /// Peers heard from since the last check-quorum.
    recent: BTreeSet<N>,
    /// Members whose node the host has not heard lately
    /// ([`Core::vouch`]): an idle leader sends them no heartbeats.
    silent: BTreeSet<N>,
    /// A leadership transfer in progress, and when it gives up.
    transfer: Option<(N, u64)>,
}

impl<N: NodeId> LeaderState<N> {
    fn new() -> Self {
        Self {
            next_index: BTreeMap::new(),
            match_index: BTreeMap::new(),
            in_flight: BTreeMap::new(),
            snapshotting: BTreeMap::new(),
            loading: BTreeSet::new(),
            round: 0,
            acked_round: BTreeMap::new(),
            sent_commit: BTreeMap::new(),
            acked_commit: BTreeMap::new(),
            answered: BTreeMap::new(),
            recent: BTreeSet::new(),
            silent: BTreeSet::new(),
            transfer: None,
        }
    }

    /// The highest index `peer` is known to hold.
    fn matched(&self, peer: N) -> u64 {
        self.match_index.get(&peer).copied().unwrap_or(0)
    }

    /// The next index to send `peer`.
    fn next(&self, peer: N) -> u64 {
        self.next_index.get(&peer).copied().unwrap_or(1)
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
    check_quorum_due: u64,
    last_heard_leader: Option<u64>,
    votes: BTreeSet<N>,
    pre_candidate_misses: u32,
    /// What a leader tracks of its followers, while it leads.
    leading: Option<LeaderState<N>>,
    reads: Vec<PendingRead>,
    pending_acks: Vec<PendingAck<N>>,
    seen_leader: Option<N>,
    current_term_first_index: Option<u64>,
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
}

impl<N: NodeId> Core<N> {
    /// A replica recovered from its store, at time `now` (milliseconds on
    /// the host's monotonic clock), with a seed for its election jitter.
    pub fn new(cfg: Config<N>, recovered: Recovered<N>, now: u64, seed: u64) -> Self {
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
            check_quorum_due: now,
            last_heard_leader: None,
            votes: BTreeSet::new(),
            pre_candidate_misses: 0,
            leading: None,
            reads: Vec::new(),
            pending_acks: Vec::new(),
            seen_leader: None,
            current_term_first_index: None,
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
        };
        core.recover_configuration(recovered.active_config);
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
        if self.role == Role::Leader && self.cfg.check_quorum && self.now >= self.check_quorum_due {
            self.check_quorum();
        }
        if self.now >= self.election_deadline {
            self.on_timer();
        }
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
            for in_flight in leading.in_flight.values() {
                deadline = deadline.min(in_flight.deadline);
            }
            for snapshotting in leading.snapshotting.values() {
                deadline = deadline.min(snapshotting.deadline);
            }
            if let Some((_, at)) = leading.transfer {
                deadline = deadline.min(at);
            }
            if self.cfg.check_quorum && !self.is_solo() {
                deadline = deadline.min(self.check_quorum_due);
            }
        }
        deadline
    }

    /// A message from `from`, already authenticated by the host.
    pub fn receive(&mut self, from: N, message: Message<N>) {
        if let Some(leading) = self.leading.as_mut()
            && message.term() == self.term
        {
            leading.recent.insert(from);
            leading.answered.insert(from, self.now);
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
        if self.role != Role::Leader {
            self.answer(Answer::ReadIndex {
                token,
                result: Err(ReadIndexError::NotLeader),
            });
            return;
        }
        if self.reads.len() >= self.cfg.max_pending_reads {
            self.answer(Answer::ReadIndex {
                token,
                result: Err(ReadIndexError::Backpressure),
            });
            return;
        }
        // A read is served at an index no lower than this term's no-op, so it
        // never sees state a later leader could revert.
        let required_index = self.commit.max(self.current_term_first_index.unwrap_or(0));
        let round = self.leading.as_ref().map_or(0, |leading| leading.round) + 1;
        self.reads.push(PendingRead {
            token,
            required_index,
            round,
            deadline: timeout_ms.map(|timeout| self.now + timeout),
        });
        if self.is_solo() {
            self.try_resolve_reads();
        } else {
            self.send_heartbeats();
        }
    }

    /// Start a membership change to `members` (joint consensus).
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
        if self.role == Role::Leader {
            self.try_advance_commit();
            self.try_resolve_reads();
            self.maybe_send_timeout_now();
        }
    }

    /// The host cannot complete the entries it never reported durable (a
    /// blob one names is lost): the replica drops those above its durable
    /// and commit indexes, as a crash would drop unsynced writes. It never
    /// acknowledged them, and an entry committed is held, with its blobs,
    /// by a quorum it can fetch them from. A candidate or a leader steps
    /// down first: its requests advertised the longer log, so no grant
    /// made against it may still count, and a leader counts only a quorum,
    /// so what it committed is kept.
    pub fn discard_unreported(&mut self) {
        let keep = self.durable_index.max(self.commit);
        if self.log.last_index() <= keep {
            return;
        }
        if self.role != Role::Follower {
            self.step_down();
        }
        self.write_truncate(keep);
        self.verified = self.verified.min(keep);
    }

    /// Streaming a snapshot to `to` failed; it goes back to probing.
    pub fn snapshot_failed(&mut self, to: N) {
        if let Some(leading) = self.leading.as_mut() {
            leading.snapshotting.remove(&to);
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

    /// Vouch for this replica's leader and members from the host's pair
    /// heartbeats, at `now`: `listed(node, term)` says when `node` last
    /// said it leads this group at `term`, `heard(node)` when `node` was
    /// last heard at all, both on the core's clock.
    ///
    /// A follower whose leader listed the group at its term within the
    /// election timeout's lower bound hears of it then. A leader counts each
    /// member heard within check-quorum's window as heard from, while the
    /// member answers it, and sends no idle heartbeats to those not heard.
    pub fn vouch(
        &mut self,
        now: u64,
        listed: impl Fn(N, u64) -> Option<u64>,
        heard: impl Fn(N) -> Option<u64>,
    ) {
        self.now = self.now.max(now);
        let (low, high) = self.cfg.election_timeout_ms;
        match self.role {
            Role::Follower => {
                if let Some(leader) = self.seen_leader
                    && let Some(at) = listed(leader, self.term)
                    && at + low > self.now
                {
                    self.heard_leader_at(at);
                }
            }
            Role::Leader => {
                let Some(leading) = self.leading.as_mut() else {
                    return;
                };
                let (me, now, last) = (self.cfg.me, self.now, self.log.last_index());
                // A member owed entries counts only while it answers over
                // Raft now and then: a leader whose frames go unanswered for
                // three times the longer of an election timeout and an
                // append's resend steps down, however alive the member's
                // node is.
                let patience = 3 * high.max(self.cfg.resend_timeout_ms);
                let mut silent = BTreeSet::new();
                for member in self.active.members().filter(|&member| member != me) {
                    if heard(member).is_none_or(|at| at + high <= now) {
                        silent.insert(member);
                    } else if leading.matched(member) >= last
                        || leading
                            .answered
                            .get(&member)
                            .is_some_and(|at| at + patience > now)
                    {
                        leading.recent.insert(member);
                    }
                }
                // A host that hears too few to make a quorum may be the one
                // gone deaf: its leader goes on sending, and lets
                // check-quorum judge by the answers.
                if !self
                    .active
                    .quorum_holds(|member| member == me || !silent.contains(&member))
                {
                    silent.clear();
                }
                leading.silent = silent;
            }
            _ => {}
        }
    }

    /// `node` came back (a new run of it, or heard again after a silence):
    /// a leader no longer counts it as caught up, and sends it a heartbeat
    /// at once, so a replica that restarted learns its leader and the
    /// commit without waiting for its own deadline.
    pub fn probe(&mut self, node: N) {
        if self.role != Role::Leader || node == self.cfg.me {
            return;
        }
        let Some(leading) = self.leading.as_mut() else {
            return;
        };
        leading.acked_commit.remove(&node);
        leading.silent.remove(&node);
        let round = leading.round;
        if self.active.contains(node) {
            self.heartbeat_to(node, round);
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
            if self
                .active
                .members()
                .any(|peer| peer != me && !self.caught_up(peer))
            {
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

    pub fn role(&self) -> Role {
        self.role
    }

    /// The highest index `peer` is known to hold, while this replica
    /// leads.
    pub fn match_index(&self, peer: N) -> Option<u64> {
        self.leading.as_ref()?.match_index.get(&peer).copied()
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
        }
    }
}
