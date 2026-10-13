//! Appends on both sides: a follower matching and acknowledging them, a
//! leader sending entries, heartbeats and commits, loading what its cache
//! lacks, and advancing its commit and its reads.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::{
    Action, Answer, Core, InFlight, Load, PendingAck, PendingRead, ReadIndexError, Snapshotting,
};
use crate::config::NodeId;
use crate::log_entry::LogEntry;
use crate::message::{AppendResult, Message};
use crate::role::Role;

/// Handovers a leader whose writer stays stalled attempts before it steps
/// down.
const STALLED_HANDOVERS: u32 = 3;

/// Take the peers whose deadline in `slots` passed by `now`, in order.
fn expired<N: NodeId, T>(
    slots: &mut BTreeMap<N, T>,
    now: u64,
    deadline: impl Fn(&T) -> u64,
) -> Vec<N> {
    let mut expired = Vec::new();
    slots.retain(|&peer, slot| {
        let live = deadline(slot) > now;
        if !live {
            expired.push(peer);
        }
        live
    });
    expired
}

impl<N: NodeId> Core<N> {
    /// An append from `from`; [`Self::receive`] passes no other message.
    pub(super) fn on_append(&mut self, from: N, append: Message<N>) {
        let Message::Append {
            term,
            leader,
            mut prev_index,
            mut prev_term,
            commit,
            round,
            mut entries,
        } = append
        else {
            return;
        };
        if leader != from {
            return;
        }
        if term < self.term {
            self.reject(from, round, commit, prev_index, (0, 0));
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
            let conflict = match self.log.term_at(prev_index) {
                Some(term) => (term, self.log.first_of_term_at(prev_index)),
                None => (0, self.log.last_index() + 1),
            };
            self.reject(from, round, commit, prev_index, conflict);
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
        let last_new = prev_index + entries.len() as u64;
        // What the log lacks, at the indexes the leader's log gives them.
        entries.drain(..present);
        for (offset, entry) in entries.iter_mut().enumerate() {
            entry.index = prev_index + 1 + (present + offset) as u64;
        }

        self.follow_membership(truncate_after, &entries);

        if let Some(after) = truncate_after {
            self.write_truncate(after);
        }
        self.write_entries(entries);
        self.verified = self.verified.max(last_new);
        self.advance_commit(commit.min(self.verified));
        self.follow_committed_membership();

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
                round,
                commit,
                upto: last_new,
            });
        }
    }

    /// Refuse an append after `rejected`, naming the conflict there: the
    /// term of this log's entry and the first index of that term, or none
    /// (0) and the index after this log's end. An append at a stale term is
    /// refused naming none at all.
    fn reject(
        &mut self,
        to: N,
        round: u64,
        commit: u64,
        rejected: u64,
        (conflict_term, conflict_first): (u64, u64),
    ) {
        let result = AppendResult::Rejected {
            rejected,
            last_index: self.log.last_index(),
            conflict_term,
            conflict_first,
        };
        self.respond(
            to,
            Message::AppendAnswer {
                term: self.term,
                round,
                commit,
                result,
            },
        );
    }

    pub(super) fn on_append_answer(
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
        // A leader tracks its configuration's members only: a late answer
        // from a replica a change removed draws nothing more.
        if !self.active.contains(from) {
            return;
        }
        let Some(leading) = self.leading.as_mut() else {
            return;
        };
        let acked = leading.acked_round.entry(from).or_insert(0);
        *acked = (*acked).max(round);
        match result {
            AppendResult::Matched { matched } => {
                let acked = leading.acked_commit.entry(from).or_insert(0);
                *acked = (*acked).max(commit.min(matched));
                if matched > leading.matched(from) {
                    leading.match_index.insert(from, matched);
                }
                let next = leading.next_index.entry(from).or_insert(1);
                *next = (*next).max(matched + 1);
                if leading
                    .in_flight
                    .get(&from)
                    .is_some_and(|in_flight| matched >= in_flight.last)
                {
                    leading.in_flight.remove(&from);
                }
                if leading
                    .snapshotting
                    .get(&from)
                    .is_some_and(|snapshotting| matched >= snapshotting.index)
                {
                    leading.snapshotting.remove(&from);
                }
                self.try_advance_commit();
                self.try_resolve_reads();
                self.maybe_send_timeout_now();
                self.replicate_to(from);
            }
            AppendResult::Rejected {
                rejected,
                last_index,
                conflict_term,
                conflict_first,
            } => {
                let next = leading.next(from);
                let floor = leading.matched(from) + 1;
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
                    let leading = self.leading.as_mut().expect("checked above");
                    leading
                        .next_index
                        .insert(from, hint.min(rejected).max(floor).max(1));
                    leading.in_flight.remove(&from);
                }
                self.try_resolve_reads();
                self.replicate_to(from);
            }
        }
    }

    pub(super) fn send_heartbeats(&mut self) {
        let me = self.cfg.me;
        let peers: Vec<N> = self.active.members().collect();
        let round = {
            let Some(leading) = self.leading.as_mut() else {
                return;
            };
            leading.round += 1;
            leading.round
        };
        // A read needs a round every member answers.
        let every = self.cfg.idle_heartbeats || !self.reads.is_empty();
        let mut sent = false;
        for peer in peers {
            if peer == me || (!every && self.caught_up(peer)) {
                continue;
            }
            self.heartbeat_to(peer, round);
            sent = true;
        }
        self.election_deadline = if every || sent {
            self.now + self.cfg.heartbeat_interval_ms
        } else {
            u64::MAX
        };
    }

    /// Send `peer` an append with no entries in `round`, then whatever
    /// entries it lacks.
    pub(super) fn heartbeat_to(&mut self, peer: N, round: u64) {
        self.append_to(peer, round, Vec::new());
        self.replicate_to(peer);
    }

    /// Whether an idle leader may leave `peer` without heartbeats: it
    /// acknowledged every entry and the commit, with nothing on its way to
    /// it, or its node has gone silent.
    pub(super) fn caught_up(&self, peer: N) -> bool {
        let Some(leading) = self.leading.as_ref() else {
            return false;
        };
        // A transfer's target hears each round, so a lost TimeoutNow is
        // sent again with its next answer.
        if leading.transfer.is_some_and(|(target, _)| target == peer) {
            return false;
        }
        leading.silent.contains(&peer)
            || (leading.matched(peer) >= self.log.last_index()
                && leading.acked_commit.get(&peer).copied().unwrap_or(0) >= self.commit
                && !leading.in_flight.contains_key(&peer)
                && !leading.snapshotting.contains_key(&peer)
                && !leading.loading.contains(&peer))
    }

    pub(super) fn replicate_all(&mut self) {
        let me = self.cfg.me;
        let peers: Vec<N> = self.active.members().collect();
        for peer in peers {
            if peer != me {
                self.replicate_to(peer);
            }
        }
    }

    /// Send `peer`, a member, the entries it lacks, unless an append or a
    /// snapshot is in flight to it.
    pub(super) fn replicate_to(&mut self, peer: N) {
        if self.role != Role::Leader || peer == self.cfg.me || !self.active.contains(peer) {
            return;
        }
        let (term, last) = (self.term, self.log.last_index());
        let (snap, snap_term) = (self.log.snap_index(), self.log.snap_term());
        let next = {
            let Some(leading) = self.leading.as_ref() else {
                return;
            };
            if leading.in_flight.contains_key(&peer)
                || leading.snapshotting.contains_key(&peer)
                || leading.loading.contains(&peer)
            {
                return;
            }
            leading.next(peer)
        };
        if next <= snap && snap > 0 {
            // The snapshot is at the log's start: its configuration is the
            // one in effect there, when known; never a guess.
            let configuration = self.log_start_config.clone();
            let deadline = self.now + self.cfg.snapshot_timeout_ms;
            if let Some(leading) = self.leading.as_mut() {
                leading.snapshotting.insert(
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
            self.send_commit(peer);
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
                if let Some(leading) = self.leading.as_mut() {
                    leading.loading.insert(peer);
                }
            }
        }
    }

    /// Send `peer` an append of `entries`, which start at its next index,
    /// and hold its in-flight slot.
    fn send_entries(&mut self, peer: N, entries: Vec<LogEntry<N>>) {
        let Some(last) = entries.last().map(|entry| entry.index) else {
            return;
        };
        let deadline = self.now + self.cfg.resend_timeout_ms;
        let Some(leading) = self.leading.as_mut() else {
            return;
        };
        if leading.in_flight.contains_key(&peer) || leading.snapshotting.contains_key(&peer) {
            return;
        }
        leading.in_flight.insert(peer, InFlight { last, deadline });
        let round = leading.round;
        self.append_to(peer, round, entries);
    }

    /// Send `peer` the commit it has not been sent, at once, in an append
    /// with no entries in the current round, holding no in-flight slot.
    fn send_commit(&mut self, peer: N) {
        let Some(leading) = self.leading.as_ref() else {
            return;
        };
        let commit = self.commit.min(leading.matched(peer));
        if commit <= leading.sent_commit.get(&peer).copied().unwrap_or(0) {
            return;
        }
        let round = leading.round;
        self.append_to(peer, round, Vec::new());
    }

    /// Send `peer` an append of `entries` in `round`, after the entry before
    /// them, or, with none, before its next index (the snapshot's at the
    /// lowest). It carries the commit, capped by what `peer` is known to
    /// hold.
    fn append_to(&mut self, peer: N, round: u64, entries: Vec<LogEntry<N>>) {
        let Some(leading) = self.leading.as_mut() else {
            return;
        };
        let prev_index = match entries.first() {
            Some(first) => first.index - 1,
            None => leading
                .next(peer)
                .saturating_sub(1)
                .max(self.log.snap_index()),
        };
        let commit = self.commit.min(leading.matched(peer));
        let sent = leading.sent_commit.entry(peer).or_insert(0);
        *sent = (*sent).max(commit);
        let message = Message::Append {
            term: self.term,
            leader: self.cfg.me,
            prev_index,
            prev_term: self.log.term_at(prev_index).unwrap_or(0),
            commit,
            round,
            entries,
        };
        self.send(peer, message);
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
            .leading
            .as_mut()
            .map(|leading| core::mem::take(&mut leading.loading).into_iter().collect())
            .unwrap_or_default();
        // A load that is empty, or starts past its first index (the store
        // compacted in between), leaves its peers to their next answer, so
        // a load that cannot help is never reissued in a loop.
        if entries.first().map(|entry| entry.index) != Some(load.from) {
            return;
        }
        for peer in waiting {
            let next = self
                .leading
                .as_ref()
                .and_then(|leading| leading.next_index.get(&peer).copied());
            if next == Some(load.from) {
                self.send_entries(peer, entries.clone());
            } else {
                self.replicate_to(peer);
            }
        }
    }

    pub(super) fn leader_timers(&mut self) {
        let now = self.now;
        let Some(leading) = self.leading.as_mut() else {
            return;
        };
        let resends = expired(&mut leading.in_flight, now, |in_flight| in_flight.deadline);
        let snapshots = expired(&mut leading.snapshotting, now, |snapshotting| {
            snapshotting.deadline
        });
        // A transfer that did not finish in time is given up, and the
        // leader takes proposals again.
        let dropped = leading.transfer.take_if(|&mut (_, at)| at <= now).is_some();
        if dropped {
            // Membership steps held back during the handover.
            self.auto_finalize_joint_config();
        }
        for peer in resends.into_iter().chain(snapshots) {
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
            self.leading
                .as_ref()
                .map_or(0, |leading| leading.matched(member))
        }
    }

    fn majority_floor(&self) -> Option<u64> {
        self.leading.as_ref()?;
        self.active
            .majority_floor(|member| self.member_score(member))
    }

    pub(super) fn try_advance_commit(&mut self) {
        let Some(floor) = self.majority_floor() else {
            return;
        };
        if self.log.term_at(floor) != Some(self.term) || !self.advance_commit(floor) {
            return;
        }
        // Followers learn it at once: entries due carry it, and an idle
        // peer gets an append with none. This comes before a committed final
        // configuration takes effect: the view is still joint, so a voter the
        // final entry removed that holds it learns it committed too, and its
        // host can retire it without waiting for the directory.
        self.replicate_all();
        self.auto_finalize_joint_config();
        let final_committed = self
            .active
            .log_index
            .is_some_and(|index| index <= self.commit);
        if self.role == Role::Leader && final_committed && !self.is_member() {
            self.step_down();
        }
        self.update_compact_bound();
    }

    /// Move the commit index up to `to`, written and announced, if that is
    /// higher. Whether it moved.
    pub(super) fn advance_commit(&mut self, to: u64) -> bool {
        if to <= self.commit {
            return false;
        }
        self.commit = to;
        self.write_meta(false);
        self.actions.push(Action::Committed { index: to });
        true
    }

    pub(super) fn try_resolve_reads(&mut self) {
        if self.reads.is_empty() {
            return;
        }
        if let Some(floor) = self.majority_floor() {
            self.answer_reads(Some(floor));
        }
    }

    /// Answer, in the order asked, every read whose deadline passed and,
    /// given `floor`, the highest index a quorum holds, every read it
    /// reaches that a round answered by a quorum since it was asked
    /// confirms.
    pub(super) fn answer_reads(&mut self, floor: Option<u64>) {
        let (me, now, solo) = (self.cfg.me, self.now, self.is_solo());
        let expired = |read: &PendingRead| read.deadline.is_some_and(|deadline| deadline <= now);
        let answered = |member, round| {
            self.leading.as_ref().is_some_and(|leading| {
                leading
                    .acked_round
                    .get(&member)
                    .is_some_and(|&acked| acked >= round)
            })
        };
        let done: Vec<PendingRead> = self
            .reads
            .extract_if(.., |read| {
                expired(read)
                    || (floor.is_some_and(|floor| read.required_index <= floor)
                        && (solo
                            || self.active.quorum_holds(|member| {
                                member == me || answered(member, read.round)
                            })))
            })
            .collect();
        for read in done {
            let result = if expired(&read) {
                Err(ReadIndexError::TimedOut)
            } else {
                Ok(read.required_index)
            };
            self.answer(Answer::ReadIndex {
                token: read.token,
                result,
            });
        }
    }

    pub(super) fn update_compact_bound(&mut self) {
        let bound = self.commit.min(self.durably_applied);
        let due = bound.saturating_sub(self.log.snap_index()) >= self.cfg.compact_hysteresis
            || self.log.bytes_through(bound) >= self.cfg.compact_bytes;
        if bound > self.compact_bound && due {
            self.compact_bound = bound;
            self.actions.push(Action::CompactBound {
                through: bound,
                configuration: self.config_at(bound),
            });
        }
    }
}
