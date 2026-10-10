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
use crate::log_entry::{EntryKind, LogEntry};
use crate::log_view::LogView;
use crate::message::{AppendResult, Message};
use crate::meta::Meta;
use crate::role::Role;
use crate::storage::ActiveConfigRecord;

/// Why a proposal was not appended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProposeError {
    /// This replica is not the leader, or is handing leadership over.
    NotLeader,
    /// The replica's driver stopped (its store failed, or it shut down).
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
    /// The replica's driver stopped. The core never returns it.
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
    /// The replica's driver stopped. The core never returns it.
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
        configuration: Option<SnapshotConfiguration<N>>,
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

/// The membership a snapshot carries, with the index that established it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotConfiguration<N: NodeId> {
    pub members: Vec<N>,
    pub joint_old: Option<Vec<N>>,
    pub index: u64,
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

/// The log start's configuration from its record.
fn start_config<N: NodeId>(record: ActiveConfigRecord<N>) -> (u64, ActiveConfig<N>) {
    (
        record.log_index.unwrap_or(0),
        ActiveConfig {
            current: record.current,
            joint_old: record.joint_old,
        },
    )
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
}

impl<N: NodeId> Default for Recovered<N> {
    fn default() -> Self {
        Self {
            meta: Meta::default(),
            entries: Vec::new(),
            active_config: None,
            log_start_config: None,
            applied: 0,
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
    pub retirement_final_index: Option<u64>,
    pub leader_hint: Option<N>,
}

// ── Configuration ──────────────────────────────────────────

/// The configuration a replica operates under; joint while `joint_old` is
/// set, when a quorum needs majorities of both sets.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ActiveConfig<N: NodeId> {
    current: Vec<N>,
    joint_old: Option<Vec<N>>,
}

impl<N: NodeId> ActiveConfig<N> {
    fn steady(members: Vec<N>) -> Self {
        Self {
            current: members,
            joint_old: None,
        }
    }

    fn is_joint(&self) -> bool {
        self.joint_old.is_some()
    }

    fn all_members(&self) -> Vec<N> {
        let mut seen = self.current.clone();
        if let Some(old) = &self.joint_old {
            for &member in old {
                if !seen.contains(&member) {
                    seen.push(member);
                }
            }
        }
        seen
    }

    fn quorum_holds(&self, mut holds: impl FnMut(N) -> bool) -> bool {
        let majority = |set: &[N], holds: &mut dyn FnMut(N) -> bool| {
            set.iter().filter(|&&member| holds(member)).count() > set.len() / 2
        };
        majority(&self.current, &mut holds)
            && self
                .joint_old
                .as_ref()
                .is_none_or(|old| majority(old, &mut holds))
    }

    /// The highest score a quorum reaches, in both sets when joint.
    fn majority_floor(&self, mut score: impl FnMut(N) -> u64) -> Option<u64> {
        let floor = |set: &[N], score: &mut dyn FnMut(N) -> u64| {
            let mut scores: Vec<u64> = set.iter().map(|&member| score(member)).collect();
            scores.sort_unstable_by(|a, b| b.cmp(a));
            let quorum = set.len() / 2 + 1;
            (quorum <= scores.len()).then(|| scores[quorum - 1])
        };
        let mut result = floor(&self.current, &mut score)?;
        if let Some(old) = &self.joint_old {
            result = result.min(floor(old, &mut score)?);
        }
        Some(result)
    }
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
    /// Peers heard from since the last check-quorum.
    recent: BTreeSet<N>,
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
            recent: BTreeSet::new(),
            transfer: None,
        }
    }
}

#[derive(Debug, Clone)]
struct PendingRead {
    token: u64,
    required_index: u64,
    round: u64,
    deadline: Option<u64>,
}

/// An acknowledgement a follower owes once its claim is durable.
#[derive(Debug, Clone, Copy)]
struct PendingAck<N: NodeId> {
    leader: N,
    term: u64,
    round: u64,
    commit: u64,
    upto: u64,
}

#[derive(Debug, Clone)]
struct OpenWrite<N: NodeId> {
    seq: u64,
    truncate_after: Option<u64>,
    entries: Vec<LogEntry<N>>,
    meta: Option<Meta<N>>,
    active_config: Option<ActiveConfigRecord<N>>,
    sync: bool,
}

#[derive(Debug, Clone, Copy)]
struct PendingWrite<N: NodeId> {
    seq: u64,
    hard: Option<(u64, Option<N>)>,
}

/// Handovers a leader whose writer stays stalled attempts before it steps
/// down.
const STALLED_HANDOVERS: u32 = 3;

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
    election_deadline: u64,
    check_quorum_due: u64,
    last_heard_leader: Option<u64>,
    votes: BTreeSet<N>,
    pre_candidate_misses: u32,
    leader: Option<LeaderState<N>>,
    reads: Vec<PendingRead>,
    pending_acks: Vec<PendingAck<N>>,
    seen_leader: Option<N>,
    current_term_first_index: Option<u64>,
    writer_stalled: bool,
    /// Handovers started since the writer stalled.
    stalled_handovers: u32,

    // Membership.
    effective: ActiveConfig<N>,
    /// The configuration in effect at the log's start, and the index of the
    /// entry that established it (0 for the static members), when known: a
    /// host that compacted without keeping it leaves it unknown.
    log_start_config: Option<(u64, ActiveConfig<N>)>,
    pending_joint_entry: Option<u64>,
    retiring_voters: BTreeMap<N, u64>,
    retiring_voter_acks: BTreeSet<N>,
    retirement_confirmation_entry: Option<u64>,
    retirement_final_index: Option<u64>,
    active_config_index: Option<u64>,

    open: Option<OpenWrite<N>>,
    next_seq: u64,
    /// The write carrying the current term, while it is not durable.
    term_seq: u64,
    writes: VecDeque<PendingWrite<N>>,
    releases: Vec<(u64, N, Message<N>)>,
    loads: BTreeSet<(u64, u64)>,
    compact_bound: u64,
    rng: u64,
    actions: Vec<Action<N>>,
    announced: Option<(u64, Role, Option<N>)>,
}

impl<N: NodeId> Core<N> {
    /// A replica recovered from its store, at time `now` (milliseconds on
    /// the host's monotonic clock), with a seed for its election jitter.
    pub fn new(cfg: Config<N>, recovered: Recovered<N>, now: u64, seed: u64) -> Self {
        let meta = recovered.meta;
        let mut log = LogView::new(meta.snap_last_index, meta.snap_last_term, cfg.cache_bytes);
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
        let mut core = Self {
            effective: ActiveConfig::steady(cfg.members.clone()),
            log_start_config: (meta.snap_last_index == 0)
                .then(|| (0, ActiveConfig::steady(cfg.members.clone()))),
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
            leader: None,
            reads: Vec::new(),
            pending_acks: Vec::new(),
            seen_leader: None,
            current_term_first_index: None,
            writer_stalled: false,
            stalled_handovers: 0,
            pending_joint_entry: None,
            retiring_voters: BTreeMap::new(),
            retiring_voter_acks: BTreeSet::new(),
            retirement_confirmation_entry: None,
            retirement_final_index: None,
            active_config_index: None,
            open: None,
            next_seq: 1,
            term_seq: 0,
            writes: VecDeque::new(),
            releases: Vec::new(),
            loads: BTreeSet::new(),
            compact_bound: meta.snap_last_index,
            rng: seed | 1,
            actions: Vec::new(),
            announced: None,
        };
        // Hosts that keep the log start's configuration say it; otherwise a
        // persisted view at or below the log's start serves.
        let snap = meta.snap_last_index;
        let start = recovered.log_start_config.or_else(|| {
            recovered
                .active_config
                .clone()
                .filter(|record| record.log_index.is_some_and(|index| index <= snap))
        });
        if let Some(record) = start {
            core.log_start_config = Some(start_config(record));
        }
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

    // ── Events ─────────────────────────────────────────────

    /// Time passes: `now` is the host's monotonic clock in milliseconds.
    pub fn tick(&mut self, now: u64) {
        self.now = self.now.max(now);
        self.expire_reads();
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
        if let Some(leader) = &self.leader {
            for in_flight in leader.in_flight.values() {
                deadline = deadline.min(in_flight.deadline);
            }
            for snapshotting in leader.snapshotting.values() {
                deadline = deadline.min(snapshotting.deadline);
            }
            if let Some((_, at)) = leader.transfer {
                deadline = deadline.min(at);
            }
            if self.cfg.check_quorum {
                deadline = deadline.min(self.check_quorum_due);
            }
        }
        deadline
    }

    /// A message from `from`, already authenticated by the host.
    pub fn receive(&mut self, from: N, message: Message<N>) {
        if let Some(leader) = self.leader.as_mut()
            && message.term() == self.term
        {
            leader.recent.insert(from);
        }
        match message {
            Message::Append {
                term,
                leader,
                prev_index,
                prev_term,
                commit,
                round,
                entries,
            } => self.on_append(
                from, term, leader, prev_index, prev_term, commit, round, entries,
            ),
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
        self.append_own(alloc::vec![LogEntry::data(index, self.term, payload)]);
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
        let round = self.leader.as_ref().map_or(0, |leader| leader.round) + 1;
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

    /// Hand leadership to `to`, or to the most up-to-date member.
    pub fn transfer_leadership(&mut self, to: Option<N>) {
        if self.role != Role::Leader {
            return;
        }
        let me = self.cfg.me;
        let target = to.or_else(|| {
            let leader = self.leader.as_ref()?;
            self.effective
                .current
                .iter()
                .copied()
                .filter(|member| *member != me)
                .max_by_key(|member| leader.match_index.get(member).copied().unwrap_or(0))
        });
        let Some(target) = target else {
            return;
        };
        if target == me || !self.effective.all_members().contains(&target) {
            return;
        }
        let deadline = self.now + self.cfg.election_timeout_ms.1;
        if let Some(leader) = self.leader.as_mut() {
            leader.transfer = Some((target, deadline));
        }
        self.maybe_send_timeout_now();
        self.replicate_to(target);
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
        let releases = core::mem::take(&mut self.releases);
        for (at, to, message) in releases {
            if at <= seq {
                self.send(to, message);
            } else {
                self.releases.push((at, to, message));
            }
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
    /// blob one names is lost): a follower drops those above its commit
    /// index, as a crash would drop unsynced writes. It never acknowledged
    /// them, and an entry committed is held, with its blobs, by a quorum
    /// it can fetch them from. A leader drops nothing: it may have counted
    /// its followers for its own entries.
    pub fn discard_unreported(&mut self) {
        let keep = self.durable_index.max(self.commit);
        if self.log.last_index() <= keep {
            return;
        }
        // A candidate's requests advertised the longer log, and a leader
        // may have counted followers for its entries: either steps down
        // first, so no grant made against that log still counts, and its
        // next candidacy advertises the shorter one.
        if self.role != Role::Follower {
            self.step_down();
        }
        self.write_truncate(keep);
        self.verified = self.verified.min(keep);
    }

    /// Forget which writes appended entries now durable.
    fn forget_written(&mut self) {
        if self.durable_index >= self.log.last_index() {
            self.written.clear();
            return;
        }
        while self
            .written
            .get(1)
            .is_some_and(|&(first, _)| first <= self.durable_index + 1)
        {
            self.written.pop_front();
        }
    }

    /// Entries the host loaded for a `LoadEntries` request.
    pub fn loaded(&mut self, load: Load, entries: Vec<LogEntry<N>>) {
        self.loads.remove(&(load.from, load.to));
        if load.term != self.term || self.role != Role::Leader {
            return;
        }
        let mut entries = self.log.loaded(entries);
        crate::log_view::cap_bytes(&mut entries, self.cfg.max_append_bytes);
        let waiting: Vec<N> = self
            .leader
            .as_mut()
            .map(|leader| core::mem::take(&mut leader.loading).into_iter().collect())
            .unwrap_or_default();
        // A load that is empty, or starts past its first index (the store
        // compacted in between), leaves its peers to their next answer, so
        // a load that cannot help is never reissued in a loop.
        if entries.first().map(|entry| entry.index) != Some(load.from) {
            return;
        }
        for peer in waiting {
            let next = self
                .leader
                .as_ref()
                .and_then(|leader| leader.next_index.get(&peer).copied());
            if next == Some(load.from) {
                self.send_entries(peer, entries.clone());
            } else {
                self.replicate_to(peer);
            }
        }
    }

    /// What switching to a received snapshot at (`index`, `term`) writes
    /// besides the state, all in one atomic batch: a crash then leaves the
    /// old replica or the new one, never a snapshot with a stale membership
    /// record. The host calls [`Self::snapshot_installed`] once it is durable.
    pub fn snapshot_switch(
        &self,
        index: u64,
        term: u64,
        configuration: Option<&SnapshotConfiguration<N>>,
    ) -> SnapshotSwitch<N> {
        let keeps_suffix = self.log.term_at(index) == Some(term);
        SnapshotSwitch {
            truncate_after: (!keeps_suffix).then_some(index),
            // The term and vote in memory are at least as new as any write
            // queued before the switch, and persisting them early is safe;
            // older ones could rewind a vote a queued write already made.
            meta: Meta {
                current_term: self.term,
                voted_for: self.vote,
                commit_index: self.commit.max(index),
                snap_last_index: index,
                snap_last_term: term,
            },
            active_config: self.snapshot_record(index, keeps_suffix, configuration),
            log_start_config: self.start_after_snapshot(index, configuration),
        }
    }

    /// The configuration in effect at an installed snapshot's index: the
    /// one it carries, else this replica's at that index, if known.
    fn start_after_snapshot(
        &self,
        index: u64,
        configuration: Option<&SnapshotConfiguration<N>>,
    ) -> Option<ActiveConfigRecord<N>> {
        match configuration.filter(|configuration| configuration.index <= index) {
            Some(configuration) => Some(ActiveConfigRecord {
                log_index: Some(configuration.index),
                current: configuration.members.clone(),
                joint_old: configuration.joint_old.clone(),
            }),
            None => self.config_at(index),
        }
    }

    /// The host switched this replica to a received snapshot, durably, with
    /// the rows of [`Self::snapshot_switch`].
    pub fn snapshot_installed(
        &mut self,
        index: u64,
        term: u64,
        configuration: Option<SnapshotConfiguration<N>>,
    ) {
        if index <= self.log.snap_index() {
            return;
        }
        let keeps_suffix = self.log.term_at(index) == Some(term);
        let record = self.snapshot_record(index, keeps_suffix, configuration.as_ref());
        self.log_start_config = self
            .start_after_snapshot(index, configuration.as_ref())
            .map(start_config);
        self.log.compact_to(index, term);
        self.durable_index = if keeps_suffix {
            self.durable_index.max(index)
        } else {
            self.written.clear();
            index
        };
        self.forget_written();
        self.verified = self.verified.max(index);
        self.adopt_snapshot_configuration(index, keeps_suffix, configuration, record);
        let previous_commit = self.commit;
        self.commit = self.commit.max(index);
        self.write_meta(true);
        if self.commit > previous_commit {
            self.actions.push(Action::Committed { index: self.commit });
        }
        if let Some(leader) = self.seen_leader {
            let matched = self.durable_index.min(self.verified);
            self.respond(
                leader,
                Message::AppendAnswer {
                    term: self.term,
                    round: 0,
                    commit: index,
                    result: AppendResult::Matched { matched },
                },
            );
        }
    }

    /// Streaming a snapshot to `to` failed; it goes back to probing.
    pub fn snapshot_failed(&mut self, to: N) {
        if let Some(leader) = self.leader.as_mut() {
            leader.snapshotting.remove(&to);
        }
    }

    /// The host made its applies through `index` durable.
    pub fn durably_applied(&mut self, index: u64) {
        self.durably_applied = self.durably_applied.max(index);
        self.update_compact_bound();
    }

    /// The host compacted its log through `through`.
    pub fn compacted(&mut self, through: u64) {
        let Some(term) = self.log.term_at(through) else {
            return;
        };
        if through <= self.log.snap_index() || through > self.compact_bound {
            return;
        }
        self.log_start_config = self.config_at(through).map(start_config);
        self.log.compact_to(through, term);
    }

    /// The configuration in effect at `index`, at or after the log's start,
    /// with the index of the entry that established it: the latest
    /// configuration entry at or below it, else the log start's, if known.
    /// A host exporting a snapshot at its applied index ships this.
    pub fn config_at(&self, index: u64) -> Option<ActiveConfigRecord<N>> {
        let from_log = self
            .log
            .configs()
            .rev()
            .find(|entry| entry.index <= index)
            .and_then(|entry| match &entry.kind {
                EntryKind::ConfigChange { joint_old, members } => Some(ActiveConfigRecord {
                    log_index: Some(entry.index),
                    current: members.clone(),
                    joint_old: joint_old.clone(),
                }),
                _ => None,
            });
        from_log.or_else(|| {
            self.log_start_config
                .as_ref()
                .map(|(at, config)| ActiveConfigRecord {
                    log_index: Some(*at),
                    current: config.current.clone(),
                    joint_old: config.joint_old.clone(),
                })
        })
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

    /// `node` answered the host's pair heartbeat: count it as heard from.
    /// The host reports it for this group only while `node`'s heartbeat
    /// says it leads the group (or follows it, for a leader's count): a
    /// node whose leader here stepped down must stop vouching for it, or
    /// its followers refuse each other's pre-votes and the group stays
    /// leaderless.
    pub fn peer_alive(&mut self, node: N) {
        if let Some(leader) = self.leader.as_mut() {
            leader.recent.insert(node);
        }
        if self.role == Role::Follower && self.seen_leader == Some(node) {
            self.last_heard_leader = Some(self.now);
        }
    }

    /// The actions since the last call, in order.
    pub fn take_actions(&mut self) -> Vec<Action<N>> {
        self.close_write();
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

    pub fn status(&self) -> Status<N> {
        Status {
            role: self.role,
            current_term: self.term,
            voted_for: self.vote,
            last_log_index: self.log.last_index(),
            commit_index: self.commit,
            snap_last_index: self.log.snap_index(),
            durable_index: self.durable_index,
            members: self.effective.current.clone(),
            joint_old: self.effective.joint_old.clone(),
            active_config_index: self.active_config_index,
            retirement_final_index: self.retirement_final_index,
            leader_hint: self.seen_leader,
        }
    }

    // ── Writes and sends ───────────────────────────────────

    fn meta(&self) -> Meta<N> {
        Meta {
            current_term: self.term,
            voted_for: self.vote,
            commit_index: self.commit,
            snap_last_index: self.log.snap_index(),
            snap_last_term: self.log.snap_term(),
        }
    }

    fn open_write(&mut self) -> &mut OpenWrite<N> {
        if self.open.is_none() {
            let seq = self.next_seq;
            self.next_seq += 1;
            self.open = Some(OpenWrite {
                seq,
                truncate_after: None,
                entries: Vec::new(),
                meta: None,
                active_config: None,
                sync: false,
            });
        }
        self.open.as_mut().expect("opened above")
    }

    fn close_write(&mut self) {
        let Some(open) = self.open.take() else {
            return;
        };
        self.writes.push_back(PendingWrite {
            seq: open.seq,
            hard: open
                .meta
                .as_ref()
                .map(|meta| (meta.current_term, meta.voted_for)),
        });
        self.actions.push(Action::Write(Write {
            seq: open.seq,
            truncate_after: open.truncate_after,
            entries: open.entries,
            meta: open.meta,
            active_config: open.active_config,
            sync: open.sync,
        }));
    }

    /// Record the hard state; `sync` when the term or vote changed.
    fn write_meta(&mut self, sync: bool) {
        let meta = self.meta();
        let write = self.open_write();
        write.meta = Some(meta);
        write.sync |= sync;
        if sync {
            self.term_seq = self.open.as_ref().expect("open").seq;
        }
    }

    fn write_truncate(&mut self, after: u64) {
        if self
            .open
            .as_ref()
            .is_some_and(|open| !open.entries.is_empty())
        {
            self.close_write();
        }
        let write = self.open_write();
        write.truncate_after = Some(write.truncate_after.map_or(after, |at| at.min(after)));
        write.sync = true;
        self.log.truncate_after(after);
        self.durable_index = self.durable_index.min(after);
        self.written.retain(|&(first, _)| first <= after);
    }

    fn write_entries(&mut self, entries: &[LogEntry<N>]) {
        if entries.is_empty() {
            return;
        }
        self.log.append(entries);
        let write = self.open_write();
        write.entries.extend_from_slice(entries);
        write.sync = true;
        let seq = write.seq;
        if self.written.back().is_none_or(|&(_, write)| write != seq) {
            self.written.push_back((entries[0].index, seq));
        }
        // Entries above the durable index may not be in the store yet.
        self.log.evict(self.durable_index + 1);
    }

    fn write_active_config(&mut self, record: ActiveConfigRecord<N>) {
        let write = self.open_write();
        write.active_config = Some(record);
        write.sync = true;
    }

    /// The leader appends its own entries.
    fn append_own(&mut self, entries: Vec<LogEntry<N>>) {
        self.write_entries(&entries);
    }

    fn send(&mut self, to: N, message: Message<N>) {
        self.actions.push(Action::Send { to, message });
    }

    /// Send now if the message's term is durable; otherwise once the write
    /// of the current term is.
    fn respond(&mut self, to: N, message: Message<N>) {
        if message.term() <= self.durable_term {
            self.send(to, message);
        } else {
            self.releases.push((self.term_seq, to, message));
        }
    }

    fn answer(&mut self, answer: Answer) {
        self.actions.push(Action::Answer(answer));
    }

    fn next_random(&mut self) -> u64 {
        self.rng ^= self.rng << 13;
        self.rng ^= self.rng >> 7;
        self.rng ^= self.rng << 17;
        self.rng
    }

    fn reset_election_timer(&mut self) {
        let (low, high) = self.cfg.election_timeout_ms;
        let span = high.saturating_sub(low).max(1);
        let jitter = self.next_random() % span;
        self.election_deadline = self.now + low + jitter;
    }

    // ── Terms and roles ────────────────────────────────────

    /// Adopt a higher term: forget the vote and the leader, step down.
    fn adopt_term(&mut self, term: u64) {
        self.term = term;
        self.vote = None;
        self.seen_leader = None;
        self.verified = self.commit;
        self.pending_acks.clear();
        self.step_down();
        self.write_meta(true);
    }

    fn step_down(&mut self) {
        if self.role == Role::Leader {
            for read in core::mem::take(&mut self.reads) {
                self.answer(Answer::ReadIndex {
                    token: read.token,
                    result: Err(ReadIndexError::LeaderStepped),
                });
            }
        }
        if self.role == Role::Leader && self.seen_leader == Some(self.cfg.me) {
            self.seen_leader = None;
        }
        self.role = Role::Follower;
        self.votes.clear();
        self.leader = None;
        self.current_term_first_index = None;
        self.pre_candidate_misses = 0;
        self.reset_election_timer();
    }

    fn on_timer(&mut self) {
        if self.writer_stalled && self.role != Role::Leader {
            // A replica that cannot write cannot vote or lead.
            self.role = Role::Follower;
            self.votes.clear();
            self.reset_election_timer();
            return;
        }
        match self.role {
            Role::Follower => {
                if self.cfg.pre_vote {
                    self.start_pre_election();
                } else {
                    self.start_election();
                }
            }
            Role::PreCandidate => {
                self.pre_candidate_misses = self.pre_candidate_misses.saturating_add(1);
                let cap = self.cfg.pre_candidate_misses_before_revert;
                if cap > 0 && self.pre_candidate_misses >= cap {
                    self.role = Role::Follower;
                    self.votes.clear();
                    self.pre_candidate_misses = 0;
                    self.reset_election_timer();
                } else {
                    self.start_pre_election();
                }
            }
            Role::Candidate => self.start_election(),
            Role::Leader => self.send_heartbeats(),
        }
    }

    fn is_member(&self) -> bool {
        self.effective.all_members().contains(&self.cfg.me)
    }

    fn is_solo(&self) -> bool {
        let only_me = |set: &Vec<N>| set.iter().all(|member| *member == self.cfg.me);
        only_me(&self.effective.current) && self.effective.joint_old.as_ref().is_none_or(only_me)
    }

    fn start_pre_election(&mut self) {
        if !self.is_member() {
            self.reset_election_timer();
            return;
        }
        if self.is_solo() {
            self.start_election();
            return;
        }
        self.role = Role::PreCandidate;
        self.votes.clear();
        self.votes.insert(self.cfg.me);
        let next_term = self.term + 1;
        let (last_index, last_term) = (self.log.last_index(), self.log.last_term());
        let me = self.cfg.me;
        for peer in self.effective.all_members() {
            if peer != me {
                self.send(
                    peer,
                    Message::PreVote {
                        next_term,
                        candidate: me,
                        last_index,
                        last_term,
                    },
                );
            }
        }
        self.reset_election_timer();
    }

    fn start_election(&mut self) {
        if !self.is_member() {
            self.reset_election_timer();
            return;
        }
        self.role = Role::Candidate;
        self.term += 1;
        self.vote = Some(self.cfg.me);
        self.seen_leader = None;
        self.verified = self.commit;
        self.pending_acks.clear();
        self.leader = None;
        self.write_meta(true);
        // The own vote counts once its write is durable.
        self.votes.clear();
        let (last_index, last_term) = (self.log.last_index(), self.log.last_term());
        let (term, me) = (self.term, self.cfg.me);
        for peer in self.effective.all_members() {
            if peer != me {
                self.send(
                    peer,
                    Message::Vote {
                        term,
                        candidate: me,
                        last_index,
                        last_term,
                    },
                );
            }
        }
        self.reset_election_timer();
    }

    fn check_election(&mut self) {
        let votes = self.votes.clone();
        if self.role == Role::Candidate
            && self
                .effective
                .quorum_holds(|member| votes.contains(&member))
        {
            self.become_leader();
        }
    }

    fn become_leader(&mut self) {
        self.role = Role::Leader;
        self.votes.clear();
        self.seen_leader = Some(self.cfg.me);
        self.leader = Some(LeaderState::new());
        self.rebuild_leader_tracking();
        // A new leader commits an entry of its own term before it serves
        // reads, so no read sees state a later leader could revert.
        let index = self.log.last_index() + 1;
        self.current_term_first_index = Some(index);
        self.append_own(alloc::vec![LogEntry::data(index, self.term, Vec::new())]);
        self.check_quorum_due = self.now + self.cfg.election_timeout_ms.1;
        self.send_heartbeats();
    }

    fn check_quorum(&mut self) {
        let me = self.cfg.me;
        let heard = self
            .leader
            .as_ref()
            .map(|leader| leader.recent.clone())
            .unwrap_or_default();
        if !self.is_solo()
            && !self
                .effective
                .quorum_holds(|member| member == me || heard.contains(&member))
        {
            self.step_down();
            return;
        }
        if let Some(leader) = self.leader.as_mut() {
            leader.recent.clear();
        }
        self.check_quorum_due = self.now + self.cfg.election_timeout_ms.1;
    }

    // ── Votes ──────────────────────────────────────────────

    fn on_vote(&mut self, from: N, term: u64, candidate: N, last_index: u64, last_term: u64) {
        if candidate != from {
            return;
        }
        if term < self.term {
            self.respond(
                from,
                Message::VoteAnswer {
                    term: self.term,
                    granted: false,
                },
            );
            return;
        }
        if term > self.term {
            self.adopt_term(term);
        }
        let up_to_date = last_term > self.log.last_term()
            || (last_term == self.log.last_term() && last_index >= self.log.last_index());
        let granted = up_to_date && self.vote.is_none_or(|vote| vote == candidate);
        let answer = Message::VoteAnswer {
            term: self.term,
            granted,
        };
        if granted {
            self.vote = Some(candidate);
            self.reset_election_timer();
            self.write_meta(true);
            // A grant leaves once the vote is durable.
            self.releases.push((self.term_seq, from, answer));
        } else {
            self.respond(from, answer);
        }
    }

    fn on_vote_answer(&mut self, from: N, term: u64, granted: bool) {
        if term > self.term {
            self.adopt_term(term);
            return;
        }
        if self.role != Role::Candidate || term != self.term || !granted {
            return;
        }
        if !self.effective.all_members().contains(&from) {
            return;
        }
        self.votes.insert(from);
        self.check_election();
    }

    fn on_pre_vote(
        &mut self,
        from: N,
        next_term: u64,
        candidate: N,
        last_index: u64,
        last_term: u64,
    ) {
        if candidate != from {
            return;
        }
        let refuse = Message::PreVoteAnswer {
            term: self.term,
            next_term,
            granted: false,
        };
        // A leader refuses, as does a follower that heard from its leader
        // recently: a pre-vote must not depose a live leader, and one that
        // stopped hearing it over a lossy link must not win.
        if next_term <= self.term || self.role == Role::Leader {
            self.send(from, refuse);
            return;
        }
        if let Some(heard) = self.last_heard_leader
            && self.now < heard + self.cfg.election_timeout_ms.0
            && self.seen_leader != Some(from)
        {
            self.send(from, refuse);
            return;
        }
        let up_to_date = last_term > self.log.last_term()
            || (last_term == self.log.last_term() && last_index >= self.log.last_index());
        self.send(
            from,
            Message::PreVoteAnswer {
                term: self.term,
                next_term,
                granted: up_to_date,
            },
        );
    }

    fn on_pre_vote_answer(&mut self, from: N, term: u64, next_term: u64, granted: bool) {
        if term > self.term {
            self.adopt_term(term);
            return;
        }
        if self.role != Role::PreCandidate || next_term != self.term + 1 || !granted {
            return;
        }
        if !self.effective.all_members().contains(&from) {
            return;
        }
        self.votes.insert(from);
        let votes = self.votes.clone();
        if self
            .effective
            .quorum_holds(|member| votes.contains(&member))
        {
            self.pre_candidate_misses = 0;
            self.start_election();
        }
    }

    fn on_timeout_now(&mut self, from: N, term: u64) {
        if term == self.term
            && self.role == Role::Follower
            && self.seen_leader == Some(from)
            && !self.writer_stalled
            && self.is_member()
        {
            self.start_election();
        }
    }

    fn transferring(&self) -> bool {
        self.leader
            .as_ref()
            .is_some_and(|leader| leader.transfer.is_some())
    }

    fn maybe_send_timeout_now(&mut self) {
        let Some(leader) = self.leader.as_ref() else {
            return;
        };
        let Some((target, _)) = leader.transfer else {
            return;
        };
        // The target holding every entry is what makes the handover safe;
        // the leader's own durability is not needed, which lets a leader
        // whose writer stalled hand over.
        if leader.match_index.get(&target).copied().unwrap_or(0) >= self.log.last_index() {
            let term = self.term;
            self.send(target, Message::TimeoutNow { term });
        }
    }

    // ── Appends: follower ──────────────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn on_append(
        &mut self,
        from: N,
        term: u64,
        leader: N,
        mut prev_index: u64,
        mut prev_term: u64,
        commit: u64,
        round: u64,
        mut entries: Vec<LogEntry<N>>,
    ) {
        if leader != from {
            return;
        }
        if term < self.term {
            self.respond(
                from,
                Message::AppendAnswer {
                    term: self.term,
                    round,
                    commit,
                    result: AppendResult::Rejected {
                        rejected: prev_index,
                        last_index: self.log.last_index(),
                        conflict_term: 0,
                        conflict_first: 0,
                    },
                },
            );
            return;
        }
        if term > self.term {
            self.adopt_term(term);
        }
        if self.role != Role::Follower {
            self.step_down();
        }
        self.reset_election_timer();
        self.last_heard_leader = Some(self.now);
        self.seen_leader = Some(leader);

        // Entries at or below the snapshot are committed, and so match.
        let snap = self.log.snap_index();
        if prev_index < snap {
            let skip = (snap - prev_index) as usize;
            entries.drain(..skip.min(entries.len()));
            prev_index = snap;
            prev_term = self.log.snap_term();
        }
        if self.log.term_at(prev_index) != Some(prev_term) {
            let last_index = self.log.last_index();
            let (conflict_term, conflict_first) = match self.log.term_at(prev_index) {
                Some(term) => (term, self.log.first_of_term_at(prev_index)),
                None => (0, last_index + 1),
            };
            self.respond(
                from,
                Message::AppendAnswer {
                    term: self.term,
                    round,
                    commit,
                    result: AppendResult::Rejected {
                        rejected: prev_index,
                        last_index,
                        conflict_term,
                        conflict_first,
                    },
                },
            );
            return;
        }

        let mut conflict_at = None;
        let mut present = 0usize;
        for (offset, entry) in entries.iter().enumerate() {
            let index = prev_index + 1 + offset as u64;
            match self.log.term_at(index) {
                Some(term) if term == entry.term => present += 1,
                Some(_) => {
                    conflict_at = Some(index);
                    break;
                }
                None => break,
            }
        }
        let truncate_after = conflict_at.map(|index| index - 1);
        let appends: Vec<LogEntry<N>> = entries
            .iter()
            .enumerate()
            .skip(present)
            .map(|(offset, entry)| LogEntry {
                index: prev_index + 1 + offset as u64,
                term: entry.term,
                kind: entry.kind.clone(),
            })
            .collect();
        let last_new = prev_index + entries.len() as u64;

        self.follow_membership(truncate_after, &appends);

        if let Some(after) = truncate_after {
            self.write_truncate(after);
        }
        self.write_entries(&appends);
        self.verified = self.verified.max(last_new);
        let previous_commit = self.commit;
        let new_commit = commit.min(self.verified);
        if new_commit > self.commit {
            self.commit = new_commit;
            self.write_meta(false);
            self.actions.push(Action::Committed { index: self.commit });
        }
        self.follow_committed_membership(previous_commit);

        let matched = self.durable_index.min(self.verified);
        self.respond(
            from,
            Message::AppendAnswer {
                term: self.term,
                round,
                commit,
                result: AppendResult::Matched { matched },
            },
        );
        if matched < last_new {
            self.pending_acks.push(PendingAck {
                leader: from,
                term: self.term,
                round,
                commit,
                upto: last_new,
            });
        }
    }

    /// Send every acknowledgement whose claim is now durable.
    fn flush_acks(&mut self) {
        let term = self.term;
        let matched = self.durable_index.min(self.verified);
        let acks = core::mem::take(&mut self.pending_acks);
        let mut keep = Vec::new();
        let mut sent: BTreeSet<N> = BTreeSet::new();
        for ack in acks.into_iter().rev() {
            if ack.term != term {
                continue;
            }
            if matched >= ack.upto {
                // The newest acknowledgement per leader covers older ones.
                if sent.insert(ack.leader) {
                    self.respond(
                        ack.leader,
                        Message::AppendAnswer {
                            term,
                            round: ack.round,
                            commit: ack.commit,
                            result: AppendResult::Matched { matched },
                        },
                    );
                }
            } else {
                keep.push(ack);
            }
        }
        keep.reverse();
        self.pending_acks = keep;
    }

    // ── Appends: leader ────────────────────────────────────

    fn on_append_answer(
        &mut self,
        from: N,
        term: u64,
        round: u64,
        commit: u64,
        result: AppendResult,
    ) {
        if term > self.term {
            self.adopt_term(term);
            return;
        }
        if self.role != Role::Leader || term != self.term {
            return;
        }
        let Some(leader) = self.leader.as_mut() else {
            return;
        };
        let acked = leader.acked_round.entry(from).or_insert(0);
        *acked = (*acked).max(round);
        match result {
            AppendResult::Matched { matched } => {
                let previous = leader.match_index.get(&from).copied().unwrap_or(0);
                if matched > previous {
                    leader.match_index.insert(from, matched);
                }
                let next = leader.next_index.entry(from).or_insert(1);
                *next = (*next).max(matched + 1);
                if leader
                    .in_flight
                    .get(&from)
                    .is_some_and(|in_flight| matched >= in_flight.last)
                {
                    leader.in_flight.remove(&from);
                }
                if leader
                    .snapshotting
                    .get(&from)
                    .is_some_and(|snapshotting| matched >= snapshotting.index)
                {
                    leader.snapshotting.remove(&from);
                }
                self.try_advance_commit();
                self.try_resolve_reads();
                let learned_final = self
                    .retiring_voters
                    .get(&from)
                    .is_some_and(|&final_index| commit >= final_index && matched >= final_index);
                if learned_final {
                    self.retiring_voter_acks.insert(from);
                    self.maybe_append_retirement_confirmation();
                }
                self.maybe_send_timeout_now();
                self.replicate_to(from);
            }
            AppendResult::Rejected {
                rejected,
                last_index,
                conflict_term,
                conflict_first,
            } => {
                let next = leader.next_index.get(&from).copied().unwrap_or(1);
                let floor = leader.match_index.get(&from).copied().unwrap_or(0) + 1;
                // Only a rejection of the current probe moves the probe.
                if rejected + 1 == next {
                    let hint = if conflict_term == 0 {
                        last_index + 1
                    } else {
                        let last_of = self.log.last_index_of_term_at_most(conflict_term);
                        if self.log.term_at(last_of) == Some(conflict_term) {
                            last_of + 1
                        } else {
                            conflict_first
                        }
                    };
                    let leader = self.leader.as_mut().expect("checked above");
                    leader
                        .next_index
                        .insert(from, hint.min(rejected).max(floor).max(1));
                    leader.in_flight.remove(&from);
                }
                self.try_resolve_reads();
                self.replicate_to(from);
            }
        }
    }

    fn send_heartbeats(&mut self) {
        let term = self.term;
        let me = self.cfg.me;
        let peers = self.replication_peers();
        let round = {
            let Some(leader) = self.leader.as_mut() else {
                return;
            };
            leader.round += 1;
            leader.round
        };
        for peer in peers {
            if peer == me {
                continue;
            }
            let (next, matched) = {
                let leader = self.leader.as_ref().expect("leader");
                (
                    leader.next_index.get(&peer).copied().unwrap_or(1),
                    leader.match_index.get(&peer).copied().unwrap_or(0),
                )
            };
            let prev_index = next.saturating_sub(1).max(self.log.snap_index());
            let prev_term = self.log.term_at(prev_index).unwrap_or(0);
            self.send(
                peer,
                Message::Append {
                    term,
                    leader: me,
                    prev_index,
                    prev_term,
                    commit: self.commit.min(matched),
                    round,
                    entries: Vec::new(),
                },
            );
            self.replicate_to(peer);
        }
        self.election_deadline = self.now + self.cfg.heartbeat_interval_ms;
    }

    fn replication_peers(&self) -> Vec<N> {
        let mut peers = self.effective.all_members();
        peers.extend(self.retiring_voters.keys().copied());
        peers.sort_unstable();
        peers.dedup();
        peers
    }

    fn replicate_all(&mut self) {
        let me = self.cfg.me;
        for peer in self.replication_peers() {
            if peer != me {
                self.replicate_to(peer);
            }
        }
    }

    /// Send `peer` the entries it lacks, unless an append or a snapshot is
    /// in flight to it.
    fn replicate_to(&mut self, peer: N) {
        if self.role != Role::Leader || peer == self.cfg.me {
            return;
        }
        let (term, last) = (self.term, self.log.last_index());
        let (snap, snap_term) = (self.log.snap_index(), self.log.snap_term());
        let next = {
            let Some(leader) = self.leader.as_ref() else {
                return;
            };
            if leader.in_flight.contains_key(&peer)
                || leader.snapshotting.contains_key(&peer)
                || leader.loading.contains(&peer)
            {
                return;
            }
            leader.next_index.get(&peer).copied().unwrap_or(1)
        };
        if next <= snap && snap > 0 {
            // The snapshot is at the log's start: its configuration is the
            // one in effect there, when known; never a guess.
            let configuration =
                self.log_start_config
                    .as_ref()
                    .map(|(index, start)| SnapshotConfiguration {
                        members: start.current.clone(),
                        joint_old: start.joint_old.clone(),
                        index: *index,
                    });
            let deadline = self.now + self.cfg.snapshot_timeout_ms;
            if let Some(leader) = self.leader.as_mut() {
                leader.snapshotting.insert(
                    peer,
                    Snapshotting {
                        index: snap,
                        deadline,
                    },
                );
            }
            self.actions.push(Action::SendSnapshot {
                to: peer,
                index: snap,
                term: snap_term,
                configuration,
            });
            return;
        }
        if next > last {
            return;
        }
        match self.log.entries(next, last, self.cfg.max_append_bytes) {
            Some(entries) => self.send_entries(peer, entries),
            None => {
                // Only the gap below the cache comes from the store; what
                // the cache holds is sent from it once the gap is filled.
                let to = self
                    .log
                    .cache_first()
                    .map_or(last, |first| first - 1)
                    .min(last);
                if self.loads.insert((next, to)) {
                    self.actions.push(Action::LoadEntries(Load {
                        from: next,
                        to,
                        term,
                        max_bytes: self.cfg.max_append_bytes,
                    }));
                }
                if let Some(leader) = self.leader.as_mut() {
                    leader.loading.insert(peer);
                }
            }
        }
    }

    /// Send `peer` an append of `entries`, which start at its next index,
    /// and hold its in-flight slot.
    fn send_entries(&mut self, peer: N, entries: Vec<LogEntry<N>>) {
        let (Some(first), Some(sent_last)) = (
            entries.first().map(|entry| entry.index),
            entries.last().map(|entry| entry.index),
        ) else {
            return;
        };
        let (term, me) = (self.term, self.cfg.me);
        let prev_index = first - 1;
        let prev_term = self.log.term_at(prev_index).unwrap_or(0);
        let deadline = self.now + self.cfg.resend_timeout_ms;
        let (matched, round) = {
            let Some(leader) = self.leader.as_mut() else {
                return;
            };
            if leader.in_flight.contains_key(&peer) || leader.snapshotting.contains_key(&peer) {
                return;
            }
            leader.in_flight.insert(
                peer,
                InFlight {
                    last: sent_last,
                    deadline,
                },
            );
            (
                leader.match_index.get(&peer).copied().unwrap_or(0),
                leader.round,
            )
        };
        self.send(
            peer,
            Message::Append {
                term,
                leader: me,
                prev_index,
                prev_term,
                commit: self.commit.min(matched),
                round,
                entries,
            },
        );
    }

    fn leader_timers(&mut self) {
        let now = self.now;
        let (expired, snapshots, dropped) = {
            let Some(leader) = self.leader.as_mut() else {
                return;
            };
            let expired: Vec<N> = leader
                .in_flight
                .iter()
                .filter(|(_, in_flight)| in_flight.deadline <= now)
                .map(|(&peer, _)| peer)
                .collect();
            for peer in &expired {
                leader.in_flight.remove(peer);
            }
            let snapshots: Vec<N> = leader
                .snapshotting
                .iter()
                .filter(|(_, snapshotting)| snapshotting.deadline <= now)
                .map(|(&peer, _)| peer)
                .collect();
            for peer in &snapshots {
                leader.snapshotting.remove(peer);
            }
            // A transfer that did not finish in time is given up, and the
            // leader takes proposals again.
            let dropped = leader.transfer.is_some_and(|(_, at)| at <= now);
            if dropped {
                leader.transfer = None;
            }
            (expired, snapshots, dropped)
        };
        if dropped {
            // Membership steps held back during the handover.
            self.auto_finalize_joint_config();
            self.maybe_append_retirement_confirmation();
        }
        for peer in expired.into_iter().chain(snapshots) {
            self.replicate_to(peer);
        }
        // A leader whose writer stays stalled keeps handing over; after a
        // few handovers that failed, it steps down and stays quiet, so a
        // peer's election takes over.
        if self.writer_stalled && !self.transferring() {
            self.stalled_handovers += 1;
            if self.stalled_handovers > STALLED_HANDOVERS {
                self.step_down();
            } else {
                self.transfer_leadership(None);
            }
        }
    }

    fn member_score(&self, member: N) -> u64 {
        if member == self.cfg.me {
            self.durable_index
        } else {
            self.leader
                .as_ref()
                .and_then(|leader| leader.match_index.get(&member).copied())
                .unwrap_or(0)
        }
    }

    fn majority_floor(&self) -> Option<u64> {
        self.leader.as_ref()?;
        self.effective
            .majority_floor(|member| self.member_score(member))
    }

    fn try_advance_commit(&mut self) {
        let Some(floor) = self.majority_floor() else {
            return;
        };
        if floor <= self.commit || self.log.term_at(floor) != Some(self.term) {
            return;
        }
        self.commit = floor;
        self.write_meta(false);
        self.actions.push(Action::Committed { index: floor });
        self.auto_finalize_joint_config();
        self.finalize_retirement_confirmation();
        let final_committed = self
            .active_config_index
            .is_some_and(|index| index <= self.commit);
        if self.role == Role::Leader && final_committed && !self.is_member() {
            self.step_down();
        }
        self.update_compact_bound();
    }

    fn try_resolve_reads(&mut self) {
        if self.reads.is_empty() {
            return;
        }
        let Some(floor) = self.majority_floor() else {
            return;
        };
        let me = self.cfg.me;
        let acked = self
            .leader
            .as_ref()
            .map(|leader| leader.acked_round.clone())
            .unwrap_or_default();
        let now = self.now;
        let solo = self.is_solo();
        let mut waiting = Vec::new();
        for read in core::mem::take(&mut self.reads) {
            let confirmed = solo
                || self.effective.quorum_holds(|member| {
                    member == me || acked.get(&member).is_some_and(|&round| round >= read.round)
                });
            if read.deadline.is_some_and(|deadline| deadline <= now) {
                self.answer(Answer::ReadIndex {
                    token: read.token,
                    result: Err(ReadIndexError::TimedOut),
                });
            } else if read.required_index <= floor && confirmed {
                self.answer(Answer::ReadIndex {
                    token: read.token,
                    result: Ok(read.required_index),
                });
            } else {
                waiting.push(read);
            }
        }
        self.reads = waiting;
    }

    fn expire_reads(&mut self) {
        let now = self.now;
        let mut waiting = Vec::new();
        for read in core::mem::take(&mut self.reads) {
            if read.deadline.is_some_and(|deadline| deadline <= now) {
                self.answer(Answer::ReadIndex {
                    token: read.token,
                    result: Err(ReadIndexError::TimedOut),
                });
            } else {
                waiting.push(read);
            }
        }
        self.reads = waiting;
    }

    fn update_compact_bound(&mut self) {
        let mut bound = self.commit.min(self.durably_applied);
        if let Some(final_index) = self.retirement_final_index {
            bound = bound.min(final_index.saturating_sub(2));
        }
        if bound > self.compact_bound
            && bound.saturating_sub(self.log.snap_index()) >= self.cfg.compact_hysteresis
        {
            self.compact_bound = bound;
            self.actions.push(Action::CompactBound {
                through: bound,
                configuration: self.config_at(bound),
            });
        }
    }

    // ── Membership ─────────────────────────────────────────

    fn rebuild_leader_tracking(&mut self) {
        let next = self.log.last_index() + 1;
        let me = self.cfg.me;
        let mut members = self.effective.all_members();
        members.extend(self.retiring_voters.keys().copied());
        members.sort_unstable();
        members.dedup();
        let Some(leader) = self.leader.as_mut() else {
            return;
        };
        for &member in &members {
            if member == me {
                continue;
            }
            leader.next_index.entry(member).or_insert(next);
            leader.match_index.entry(member).or_insert(0);
        }
        leader
            .next_index
            .retain(|member, _| members.contains(member));
        leader
            .match_index
            .retain(|member, _| members.contains(member));
        leader
            .in_flight
            .retain(|member, _| members.contains(member));
        leader
            .snapshotting
            .retain(|member, _| members.contains(member));
        leader
            .acked_round
            .retain(|member, _| members.contains(member));
    }

    fn start_membership_change(&mut self, members: Vec<N>) -> Result<u64, ChangeMembershipError> {
        if self.role != Role::Leader || self.transferring() {
            return Err(ChangeMembershipError::NotLeader);
        }
        if self.effective.is_joint() || self.retirement_final_index.is_some() {
            return Err(ChangeMembershipError::InProgress);
        }
        if members.is_empty() {
            return Err(ChangeMembershipError::EmptyConfig);
        }
        let index = self.log.last_index() + 1;
        let old = self.effective.current.clone();
        self.append_own(alloc::vec![LogEntry::config_change(
            index,
            self.term,
            Some(old.clone()),
            members.clone(),
        )]);
        self.write_active_config(ActiveConfigRecord {
            log_index: Some(index),
            current: members.clone(),
            joint_old: Some(old.clone()),
        });
        // The joint configuration applies at once, before it commits.
        self.effective = ActiveConfig {
            current: members,
            joint_old: Some(old),
        };
        self.pending_joint_entry = Some(index);
        self.active_config_index = Some(index);
        self.rebuild_leader_tracking();
        self.try_advance_commit();
        self.replicate_all();
        Ok(index)
    }

    /// Advance a committed membership transition: a committed joint entry
    /// appends the final one; a committed final entry becomes effective.
    fn auto_finalize_joint_config(&mut self) {
        // Not while handing over: the target must hold the whole log.
        if self.role != Role::Leader || !self.effective.is_joint() || self.transferring() {
            return;
        }
        let Some(pending) = self.pending_joint_entry else {
            return;
        };
        if self.commit < pending {
            return;
        }
        let Some(entry) = self.log.entry(pending) else {
            return;
        };
        let EntryKind::ConfigChange { joint_old, members } = entry.kind else {
            return;
        };
        if joint_old.is_none() {
            self.write_active_config(ActiveConfigRecord {
                log_index: Some(pending),
                current: members.clone(),
                joint_old: None,
            });
            self.effective = ActiveConfig::steady(members);
            self.pending_joint_entry = None;
            self.active_config_index = Some(pending);
            self.rebuild_leader_tracking();
            return;
        }
        let index = self.log.last_index() + 1;
        let retiring = joint_old.unwrap_or_default();
        self.append_own(alloc::vec![LogEntry::config_change(
            index,
            self.term,
            None,
            members.clone(),
        )]);
        let mut removed_any = false;
        for voter in retiring {
            if !members.contains(&voter) {
                removed_any = true;
                if voter != self.cfg.me {
                    self.retiring_voters.insert(voter, index);
                }
            }
        }
        self.retirement_final_index = removed_any.then_some(index);
        self.retirement_confirmation_entry = None;
        self.retiring_voter_acks.clear();
        // The joint view stays effective until this final entry commits, so a
        // retiring leader that crashes can still recover and replicate it.
        self.pending_joint_entry = Some(index);
        self.rebuild_leader_tracking();
        self.replicate_all();
    }

    /// Once every removed voter has acknowledged the committed final
    /// configuration, append a confirmation that restates it.
    fn maybe_append_retirement_confirmation(&mut self) {
        if self.role != Role::Leader
            || self.transferring()
            || self.retirement_final_index.is_none()
            || self.retirement_confirmation_entry.is_some()
            || self.retiring_voters.is_empty()
            || !self
                .retiring_voters
                .keys()
                .all(|voter| self.retiring_voter_acks.contains(voter))
        {
            return;
        }
        let index = self.log.last_index() + 1;
        let members = self.effective.current.clone();
        self.append_own(alloc::vec![LogEntry::config_change(
            index,
            self.term,
            None,
            members.clone(),
        )]);
        self.write_active_config(ActiveConfigRecord {
            log_index: Some(index),
            current: members,
            joint_old: None,
        });
        self.retirement_confirmation_entry = Some(index);
        self.active_config_index = Some(index);
        self.try_advance_commit();
        self.replicate_all();
    }

    fn finalize_retirement_confirmation(&mut self) {
        if self
            .retirement_confirmation_entry
            .is_none_or(|index| index > self.commit)
        {
            return;
        }
        self.retirement_confirmation_entry = None;
        self.retirement_final_index = None;
        self.retiring_voters.clear();
        self.retiring_voter_acks.clear();
        self.rebuild_leader_tracking();
    }

    /// A follower's view of membership after an append: truncated rows drop
    /// their configurations, appended rows adopt theirs.
    fn follow_membership(&mut self, truncate_after: Option<u64>, appends: &[LogEntry<N>]) {
        let invalidated_config = match (truncate_after, self.active_config_index) {
            (Some(after), Some(index)) => after < index,
            _ => false,
        };
        let invalidated_pending = match (truncate_after, self.pending_joint_entry) {
            (Some(after), Some(index)) => after < index,
            _ => false,
        };
        let appended_config = appends
            .iter()
            .any(|entry| matches!(entry.kind, EntryKind::ConfigChange { .. }));

        let mut retiring = self.retiring_voters.clone();
        let mut final_index = self.retirement_final_index;
        let mut confirmation = self.retirement_confirmation_entry;
        let mut acks = self.retiring_voter_acks.clone();
        if let Some(after) = truncate_after {
            retiring.retain(|_, index| *index <= after);
            if final_index.is_some_and(|index| index > after) {
                final_index = None;
                confirmation = None;
                acks.clear();
            } else if confirmation.is_some_and(|index| index > after) {
                confirmation = None;
                acks.clear();
            }
        }
        let truncated_base = invalidated_config.then(|| {
            let after = truncate_after.expect("invalidation implies a truncation");
            self.log
                .configs()
                .rev()
                .find(|entry| entry.index <= after)
                .and_then(|entry| match &entry.kind {
                    EntryKind::ConfigChange { joint_old, members } => Some((
                        entry.index,
                        ActiveConfig {
                            current: members.clone(),
                            joint_old: joint_old.clone(),
                        },
                    )),
                    _ => None,
                })
                // Unknown at the log's start (a host that kept no
                // record): the static members, the best left.
                .or_else(|| self.log_start_config.clone())
                .unwrap_or_else(|| (0, ActiveConfig::steady(self.cfg.members.clone())))
        });

        let mut record = None;
        let mut view: Option<(ActiveConfig<N>, Option<u64>, Option<u64>)> = None;
        if appended_config {
            let mut retirement_view = truncated_base
                .as_ref()
                .map_or_else(|| self.effective.clone(), |(_, active)| active.clone());
            for entry in appends {
                if let EntryKind::ConfigChange { joint_old, members } = &entry.kind {
                    if let Some(old) = joint_old {
                        retirement_view = ActiveConfig {
                            current: members.clone(),
                            joint_old: Some(old.clone()),
                        };
                        final_index = None;
                        confirmation = None;
                        retiring.clear();
                        acks.clear();
                    } else if final_index.is_some()
                        && confirmation.is_none()
                        && retirement_view.current == *members
                    {
                        confirmation = Some(entry.index);
                        retirement_view = ActiveConfig::steady(members.clone());
                    } else if retirement_view.is_joint() && retirement_view.current == *members {
                        let removed_any = retirement_view
                            .joint_old
                            .as_ref()
                            .is_some_and(|old| old.iter().any(|voter| !members.contains(voter)));
                        final_index = removed_any.then_some(entry.index);
                        confirmation = None;
                        retiring.clear();
                        acks.clear();
                        if let Some(old) = &retirement_view.joint_old {
                            for voter in old {
                                if *voter != self.cfg.me && !members.contains(voter) {
                                    retiring.insert(*voter, entry.index);
                                }
                            }
                        }
                        retirement_view = ActiveConfig::steady(members.clone());
                    } else {
                        retirement_view = ActiveConfig::steady(members.clone());
                    }
                }
            }
            if let Some(entry) = appends
                .iter()
                .rev()
                .find(|entry| matches!(entry.kind, EntryKind::ConfigChange { .. }))
                && let EntryKind::ConfigChange { joint_old, members } = &entry.kind
            {
                let active = ActiveConfig {
                    current: members.clone(),
                    joint_old: joint_old.clone(),
                };
                let pending = active.is_joint().then_some(entry.index);
                record = Some(ActiveConfigRecord {
                    log_index: Some(entry.index),
                    current: members.clone(),
                    joint_old: joint_old.clone(),
                });
                view = Some((active, Some(entry.index), pending));
            }
        } else if let Some((index, active)) = truncated_base {
            let pending = active.is_joint().then_some(index);
            record = Some(ActiveConfigRecord {
                log_index: Some(index),
                current: active.current.clone(),
                joint_old: active.joint_old.clone(),
            });
            view = Some((active, Some(index), pending));
        }

        let retiring_changed = retiring != self.retiring_voters;
        self.retiring_voters = retiring;
        self.retiring_voter_acks = acks;
        self.retirement_final_index = final_index;
        self.retirement_confirmation_entry = confirmation;
        if let Some(record) = record {
            self.write_active_config(record);
        }
        if let Some((active, index, pending)) = view {
            self.effective = active;
            self.active_config_index = index;
            self.pending_joint_entry = pending;
            self.rebuild_leader_tracking();
        } else if invalidated_pending {
            self.pending_joint_entry = if self.effective.is_joint() {
                self.active_config_index
            } else {
                None
            };
        } else if retiring_changed {
            self.rebuild_leader_tracking();
        }
    }

    /// A follower whose commit index crossed a pending final configuration
    /// adopts it, and a committed confirmation clears the retirement.
    fn follow_committed_membership(&mut self, _previous_commit: u64) {
        if self.effective.is_joint()
            && let Some(pending) = self.pending_joint_entry
            && pending <= self.commit
            && let Some(entry) = self.log.entry(pending)
            && let EntryKind::ConfigChange {
                joint_old: None,
                members,
            } = entry.kind
        {
            self.write_active_config(ActiveConfigRecord {
                log_index: Some(pending),
                current: members.clone(),
                joint_old: None,
            });
            self.effective = ActiveConfig::steady(members);
            self.active_config_index = Some(pending);
            self.pending_joint_entry = None;
            self.rebuild_leader_tracking();
        }
        if self
            .retirement_confirmation_entry
            .is_some_and(|index| index <= self.commit)
        {
            self.retirement_final_index = None;
            self.retirement_confirmation_entry = None;
            self.retiring_voters.clear();
            self.retiring_voter_acks.clear();
        }
    }

    /// The membership record after a snapshot at `index`: the current view
    /// if the kept log holds a configuration entry above the snapshot, else
    /// the snapshot's configuration, else the current view, whose
    /// provenance survives only if it was committed before the install.
    fn snapshot_record(
        &self,
        index: u64,
        keeps_suffix: bool,
        configuration: Option<&SnapshotConfiguration<N>>,
    ) -> ActiveConfigRecord<N> {
        let live_above = keeps_suffix
            && self
                .log
                .configs()
                .next_back()
                .is_some_and(|entry| entry.index > index);
        match configuration.filter(|configuration| configuration.index <= index) {
            Some(configuration) if !live_above => ActiveConfigRecord {
                log_index: Some(configuration.index),
                current: configuration.members.clone(),
                joint_old: configuration.joint_old.clone(),
            },
            _ => ActiveConfigRecord {
                log_index: if live_above {
                    self.active_config_index
                } else {
                    self.active_config_index.filter(|&at| at <= self.commit)
                },
                current: self.effective.current.clone(),
                joint_old: self.effective.joint_old.clone(),
            },
        }
    }

    /// Adopt `record`, from [`Self::snapshot_record`] before the install.
    fn adopt_snapshot_configuration(
        &mut self,
        index: u64,
        keeps_suffix: bool,
        configuration: Option<SnapshotConfiguration<N>>,
        record: ActiveConfigRecord<N>,
    ) {
        if self
            .retirement_final_index
            .is_some_and(|final_index| final_index <= index)
        {
            self.retirement_final_index = None;
            self.retirement_confirmation_entry = None;
            self.retiring_voters.clear();
            self.retiring_voter_acks.clear();
        } else {
            self.retiring_voters
                .retain(|_, final_index| *final_index > index);
        }
        // After compaction, only configuration entries above `index` remain.
        let live_above = keeps_suffix && self.log.configs().next_back().is_some();
        let from_snapshot =
            !live_above && configuration.is_some_and(|configuration| configuration.index <= index);
        if from_snapshot {
            self.effective = ActiveConfig {
                current: record.current.clone(),
                joint_old: record.joint_old.clone(),
            };
            self.pending_joint_entry = None;
            self.rebuild_leader_tracking();
        } else if self.pending_joint_entry.is_some_and(|at| at <= index) {
            self.pending_joint_entry = None;
        }
        self.active_config_index = record.log_index;
        self.write_active_config(record);
    }

    /// Recover the effective configuration from the live log's latest
    /// configuration entry, else the persisted record, else the static
    /// members.
    fn recover_configuration(&mut self, persisted: Option<ActiveConfigRecord<N>>) {
        let configs: Vec<LogEntry<N>> = self.log.configs().cloned().collect();
        let commit = self.commit;
        let me = self.cfg.me;
        let Some(latest) = configs.last() else {
            if let Some(record) = persisted {
                self.effective = ActiveConfig {
                    current: record.current,
                    joint_old: record.joint_old,
                };
                self.active_config_index = record.log_index;
            } else {
                let (index, start) = self
                    .log_start_config
                    .clone()
                    .unwrap_or_else(|| (0, ActiveConfig::steady(self.cfg.members.clone())));
                self.effective = start;
                self.active_config_index = Some(index);
            }
            return;
        };
        let EntryKind::ConfigChange { joint_old, members } = &latest.kind else {
            return;
        };
        let latest_position = configs.len() - 1;
        // A second consecutive steady configuration with the same members is
        // the retirement confirmation.
        let prior_final = if joint_old.is_none() {
            configs[..latest_position]
                .iter()
                .enumerate()
                .next_back()
                .and_then(|(position, entry)| match &entry.kind {
                    EntryKind::ConfigChange {
                        joint_old: None,
                        members: prior,
                    } if prior == members => Some((position, entry.index)),
                    _ => None,
                })
        } else {
            None
        };
        let is_confirmation = prior_final.is_some();
        let joint_scan_end = prior_final.map_or(latest_position, |(position, _)| position);
        let prior_joint = if joint_old.is_none() {
            let from_log =
                configs[..joint_scan_end]
                    .iter()
                    .rev()
                    .find_map(|entry| match &entry.kind {
                        EntryKind::ConfigChange {
                            joint_old: Some(old),
                            members: joint_members,
                        } if joint_members == members => Some((
                            ActiveConfig {
                                current: joint_members.clone(),
                                joint_old: Some(old.clone()),
                            },
                            entry.index,
                        )),
                        _ => None,
                    });
            from_log.or_else(|| {
                let record = persisted.as_ref()?;
                let old = record.joint_old.clone()?;
                (record.current == *members).then(|| {
                    (
                        ActiveConfig {
                            current: record.current.clone(),
                            joint_old: Some(old),
                        },
                        record.log_index.unwrap_or(0),
                    )
                })
            })
        } else {
            None
        };
        let source_final = prior_final.map_or(latest.index, |(_, index)| index);
        let confirmation_committed = is_confirmation && latest.index <= commit;
        let mut retiring = BTreeMap::new();
        let mut removed_any = false;
        if let Some((prior, _)) = &prior_joint
            && let Some(old) = &prior.joint_old
        {
            for voter in old {
                if !members.contains(voter) {
                    removed_any = true;
                    if *voter != me && !confirmation_committed {
                        retiring.insert(*voter, source_final);
                    }
                }
            }
        }
        self.retiring_voters = retiring;
        self.retirement_final_index =
            (removed_any && !confirmation_committed).then_some(source_final);
        self.retirement_confirmation_entry =
            (is_confirmation && !confirmation_committed).then_some(latest.index);
        // A retiring leader that appended, but did not commit, the final
        // configuration excluding itself keeps the joint view, so it can still
        // campaign and replicate that final entry.
        if joint_old.is_none()
            && !is_confirmation
            && latest.index > commit
            && !members.contains(&me)
            && let Some((active, active_index)) = prior_joint
            && active
                .joint_old
                .as_ref()
                .is_some_and(|old| old.contains(&me))
        {
            self.effective = active;
            self.pending_joint_entry = Some(latest.index);
            self.active_config_index = Some(active_index);
            return;
        }
        self.effective = ActiveConfig {
            current: members.clone(),
            joint_old: joint_old.clone(),
        };
        self.pending_joint_entry = self.effective.is_joint().then_some(latest.index);
        self.active_config_index = Some(latest.index);
    }
}
