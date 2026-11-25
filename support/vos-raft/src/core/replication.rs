//! Appends on both sides: a follower matching and acknowledging them, a
//! leader sending entries, heartbeats and commits, loading what its cache
//! lacks, and advancing its commit and its reads.

use alloc::vec::Vec;

use super::{Action, Answer, Core, Load, PendingAck, PendingRead, ReadIndexError, Sending};
use crate::config::NodeId;
use crate::log_entry::LogEntry;
use crate::message::{AppendResult, Message};
use crate::role::Role;

/// Handovers a leader whose writer stays stalled attempts before it steps
/// down.
const STALLED_HANDOVERS: u32 = 3;

impl<N: NodeId> Core<N> {
    /// An append from `from`; [`Self::receive`] passes no other message.
    ///
    /// Refused whole, before it changes anything: one at this replica's
    /// term while it leads it or follows another leader at it (a term has
    /// one leader), and one whose first entry that differs from this log
    /// is at or below the commit index (no leader replaces a committed
    /// entry). A correct leader sends neither.
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
        // A leader led its term: `led` says so.
        let another = term == self.term
            && (self.led == Some(term) || self.seen_leader.is_some_and(|seen| seen != from));
        if another {
            self.refused += 1;
            return;
        }

        // Entries at or below the snapshot are committed, and so match.
        let snap = self.log.snap_index();
        if prev_index < snap {
            let skip = usize::try_from(snap - prev_index).unwrap_or(usize::MAX);
            entries.drain(..skip.min(entries.len()));
            prev_index = snap;
            prev_term = self.log.snap_term();
        }
        let matches = self.log.term_at(prev_index) == Some(prev_term);
        let mut conflict_at = None;
        let mut present = 0usize;
        if matches {
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
        }
        if conflict_at.is_some_and(|index| index <= self.commit) {
            self.refused += 1;
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
        if !matches {
            let conflict = match self.log.term_at(prev_index) {
                Some(term) => (term, self.log.first_of_term_at(prev_index)),
                None => (0, self.log.last_index() + 1),
            };
            self.reject(from, round, commit, prev_index, conflict);
            return;
        }

        let truncate_after = conflict_at.map(|index| index - 1);
        let last_new = prev_index + entries.len() as u64;
        // What the log lacks, at the indexes the leader's log gives them.
        entries.drain(..present);
        for (offset, entry) in entries.iter_mut().enumerate() {
            entry.index = prev_index + 1 + (present + offset) as u64;
        }

        // The truncation first: the membership record that falls back, or
        // that an appended configuration entry sets, goes in the write that
        // holds the change, never in an earlier one a crash could keep
        // alone.
        if let Some(after) = truncate_after {
            self.write_truncate(after);
        }
        self.follow_membership(truncate_after, &entries);
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
            // A resend of the same entries renews the acknowledgement owed
            // for them, rather than owing another.
            let ack = PendingAck {
                leader: from,
                round,
                commit,
                upto: last_new,
            };
            match self
                .pending_acks
                .iter_mut()
                .find(|owed| owed.leader == from && owed.upto == last_new)
            {
                Some(owed) => *owed = ack,
                None => self.pending_acks.push(ack),
            }
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
        if term != self.term {
            return;
        }
        let last = self.log.last_index();
        let Some(leading) = self.leading.as_mut() else {
            return;
        };
        let sent = leading.round;
        let Some(progress) = leading.peers.get_mut(&from) else {
            return;
        };
        // No answer is to a round not yet sent, or holds past this log.
        progress.acked_round = progress.acked_round.max(round.min(sent));
        match result {
            AppendResult::Matched { matched } => {
                let matched = matched.min(last);
                progress.acked_commit = progress.acked_commit.max(commit.min(matched));
                progress.matched = progress.matched.max(matched);
                progress.next = progress.next.max(matched.saturating_add(1));
                if progress
                    .in_flight
                    .is_some_and(|in_flight| matched >= in_flight.last)
                {
                    progress.in_flight = None;
                }
                if progress
                    .snapshotting
                    .is_some_and(|snapshotting| matched >= snapshotting.last)
                {
                    progress.snapshotting = None;
                }
                self.leader_progress();
                self.replicate_to(from);
            }
            AppendResult::Rejected {
                rejected,
                last_index,
                conflict_term,
                conflict_first,
            } => {
                let next = progress.next;
                let floor = progress.matched.saturating_add(1);
                // Only a rejection of the current probe moves the probe,
                // and is answered at once; one that cannot move it waits
                // for the resend, so a follower that lost what it
                // acknowledged is not probed in a loop.
                if rejected.checked_add(1) == Some(next) {
                    let hint = if conflict_term == 0 {
                        last_index.saturating_add(1)
                    } else {
                        let last_of = self.log.last_index_of_term_at_most(conflict_term);
                        if self.log.term_at(last_of) == Some(conflict_term) {
                            last_of + 1
                        } else {
                            conflict_first
                        }
                    };
                    let moved = hint.min(rejected).max(floor).max(1);
                    if moved != next {
                        progress.next = moved;
                        progress.in_flight = None;
                    }
                }
                self.try_resolve_reads();
                self.replicate_to(from);
            }
        }
    }

    pub(super) fn send_heartbeats(&mut self) {
        let peers: Vec<N> = self.active.others(self.cfg.me).collect();
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
            if !every && self.caught_up(peer) {
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
        leading.peers.get(&peer).is_some_and(|progress| {
            progress.silent
                || (progress.matched >= self.log.last_index()
                    && progress.acked_commit >= self.commit
                    && progress.in_flight.is_none()
                    && progress.snapshotting.is_none()
                    && !progress.loading)
        })
    }

    pub(super) fn replicate_all(&mut self) {
        let peers: Vec<N> = self.active.others(self.cfg.me).collect();
        for peer in peers {
            self.replicate_to(peer);
        }
    }

    /// Send `peer`, a member, the entries it lacks, unless an append or a
    /// snapshot is in flight to it.
    pub(super) fn replicate_to(&mut self, peer: N) {
        if peer == self.cfg.me || !self.active.contains(peer) {
            return;
        }
        let (term, last) = (self.term, self.log.last_index());
        let (snap, snap_term) = (self.log.snap_index(), self.log.snap_term());
        let Some(progress) = self
            .leading
            .as_mut()
            .and_then(|leading| leading.peers.get_mut(&peer))
        else {
            return;
        };
        if progress.in_flight.is_some() || progress.snapshotting.is_some() || progress.loading {
            return;
        }
        let next = progress.next;
        if next <= snap && snap > 0 {
            progress.snapshotting = Some(Sending {
                last: snap,
                deadline: self.now + self.cfg.snapshot_timeout_ms,
            });
            // The snapshot is at the log's start: its configuration is the
            // one in effect there, when known; never a guess.
            self.actions.push(Action::SendSnapshot {
                to: peer,
                index: snap,
                term: snap_term,
                configuration: self.log_start_config.clone(),
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
                progress.loading = true;
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
        let round = leading.round;
        let Some(progress) = leading.peers.get_mut(&peer) else {
            return;
        };
        if progress.in_flight.is_some() || progress.snapshotting.is_some() {
            return;
        }
        progress.in_flight = Some(Sending { last, deadline });
        self.append_to(peer, round, entries);
    }

    /// Send `peer` the commit it has not been sent, at once, in an append
    /// with no entries in the current round, holding no in-flight slot.
    fn send_commit(&mut self, peer: N) {
        let Some(leading) = self.leading.as_ref() else {
            return;
        };
        let Some(progress) = leading.peers.get(&peer) else {
            return;
        };
        if self.commit.min(progress.matched) <= progress.sent_commit {
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
        let mut progress = leading.peers.get_mut(&peer);
        let (next, matched) = progress
            .as_ref()
            .map_or((1, 0), |progress| (progress.next, progress.matched));
        let prev_index = match entries.first() {
            Some(first) => first.index - 1,
            None => next.saturating_sub(1).max(self.log.snap_index()),
        };
        let commit = self.commit.min(matched);
        if let Some(progress) = progress.as_mut() {
            progress.sent_commit = progress.sent_commit.max(commit);
        }
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
            .map(|leading| {
                let loading = leading
                    .peers
                    .iter_mut()
                    .filter(|(_, progress)| progress.loading);
                loading
                    .map(|(&peer, progress)| {
                        progress.loading = false;
                        peer
                    })
                    .collect()
            })
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
                .and_then(|leading| leading.peers.get(&peer))
                .map(|progress| progress.next);
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
        // The peers whose append or snapshot timed out, in order.
        let (mut resends, mut snapshots) = (Vec::new(), Vec::new());
        for (&peer, progress) in &mut leading.peers {
            if progress
                .in_flight
                .take_if(|sent| sent.deadline <= now)
                .is_some()
            {
                resends.push(peer);
            }
            if progress
                .snapshotting
                .take_if(|sent| sent.deadline <= now)
                .is_some()
            {
                snapshots.push(peer);
            }
        }
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
            self.leading
                .as_ref()
                .and_then(|leading| leading.peers.get(&member))
                .is_some_and(|progress| progress.acked_round >= round)
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
            || self.log.weight_through(bound) >= self.cfg.compact_bytes;
        if bound > self.compact_bound && due {
            self.compact_bound = bound;
            self.actions.push(Action::CompactBound {
                through: bound,
                configuration: self.config_at(bound),
            });
        }
    }
}
