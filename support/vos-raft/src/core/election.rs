//! Terms and roles: the election timer, pre-votes and votes, check-quorum
//! and leadership transfer.

use alloc::vec::Vec;

use super::{Answer, Core, LeaderState, ReadIndexError};
use crate::config::NodeId;
use crate::log_entry::LogEntry;
use crate::message::Message;
use crate::role::Role;

impl<N: NodeId> Core<N> {
    /// An election timeout drawn from the configured range.
    fn election_timeout(&mut self) -> u64 {
        let (low, high) = self.cfg.election_timeout_ms;
        let span = high.saturating_sub(low).max(1);
        low + self.rng.next_u64() % span
    }

    pub(super) fn reset_election_timer(&mut self) {
        self.election_deadline = self.now + self.election_timeout();
    }

    /// The host vouches that this replica's leader was alive and leading at
    /// `at`, by a heartbeat of its own: a follower takes that as having
    /// heard the leader then, when it is later than the last time it did,
    /// and its election deadline runs from it.
    pub(super) fn heard_leader_at(&mut self, at: u64) {
        if self.role != Role::Follower
            || self.seen_leader.is_none()
            || self.last_heard_leader.is_some_and(|heard| heard >= at)
        {
            return;
        }
        self.last_heard_leader = Some(at);
        self.election_deadline = self.election_deadline.max(at + self.election_timeout());
    }

    /// Adopt a higher term: forget the vote and the leader, step down.
    pub(super) fn adopt_term(&mut self, term: u64) {
        self.term = term;
        self.vote = None;
        self.seen_leader = None;
        self.verified = self.commit;
        self.pending_acks.clear();
        self.step_down();
        self.write_meta(true);
    }

    pub(super) fn step_down(&mut self) {
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
        self.leading = None;
        self.current_term_first_index = None;
        self.pre_candidate_misses = 0;
        self.reset_election_timer();
    }

    pub(super) fn on_timer(&mut self) {
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
                    self.step_down();
                } else {
                    self.start_pre_election();
                }
            }
            Role::Candidate => self.start_election(),
            Role::Leader => self.send_heartbeats(),
        }
    }

    pub(super) fn is_member(&self) -> bool {
        self.active.contains(self.cfg.me)
    }

    pub(super) fn is_solo(&self) -> bool {
        self.active.members().all(|member| member == self.cfg.me)
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
        self.broadcast(Message::PreVote {
            next_term: self.term + 1,
            candidate: self.cfg.me,
            last_index: self.log.last_index(),
            last_term: self.log.last_term(),
        });
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
        self.leading = None;
        self.write_meta(true);
        // The own vote counts once its write is durable.
        self.votes.clear();
        self.broadcast(Message::Vote {
            term: self.term,
            candidate: self.cfg.me,
            last_index: self.log.last_index(),
            last_term: self.log.last_term(),
        });
        self.reset_election_timer();
    }

    pub(super) fn check_election(&mut self) {
        if self.role == Role::Candidate
            && self
                .active
                .quorum_holds(|member| self.votes.contains(&member))
        {
            self.become_leader();
        }
    }

    fn become_leader(&mut self) {
        self.role = Role::Leader;
        self.votes.clear();
        self.seen_leader = Some(self.cfg.me);
        self.leading = Some(LeaderState::new());
        self.rebuild_leader_tracking();
        // A new leader commits an entry of its own term before it serves
        // reads, so no read sees state a later leader could revert.
        let index = self.log.last_index() + 1;
        self.current_term_first_index = Some(index);
        self.write_entries(alloc::vec![LogEntry::data(index, self.term, Vec::new())]);
        self.check_quorum_due = self.now + self.cfg.election_timeout_ms.1;
        self.send_heartbeats();
    }

    pub(super) fn check_quorum(&mut self) {
        let me = self.cfg.me;
        let heard = |member| {
            self.leading
                .as_ref()
                .is_some_and(|leading| leading.recent.contains(&member))
        };
        if !self.is_solo()
            && !self
                .active
                .quorum_holds(|member| member == me || heard(member))
        {
            self.step_down();
            return;
        }
        if let Some(leading) = self.leading.as_mut() {
            leading.recent.clear();
        }
        self.check_quorum_due = self.now + self.cfg.election_timeout_ms.1;
    }

    /// Whether a candidate whose log ends at (`last_index`, `last_term`)
    /// holds everything this replica holds, or held before a wipe.
    fn log_reached(&self, last_index: u64, last_term: u64) -> bool {
        let mut own = (self.log.last_term(), self.log.last_index());
        if let Some((index, term)) = self.vote_floor {
            own = own.max((term, index));
        }
        (last_term, last_index) >= own
    }

    pub(super) fn on_vote(
        &mut self,
        from: N,
        term: u64,
        candidate: N,
        last_index: u64,
        last_term: u64,
    ) {
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
        let granted = self.log_reached(last_index, last_term)
            && self.vote.is_none_or(|vote| vote == candidate);
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

    pub(super) fn on_vote_answer(&mut self, from: N, term: u64, granted: bool) {
        if term > self.term {
            self.adopt_term(term);
            return;
        }
        if self.role != Role::Candidate || term != self.term || !granted {
            return;
        }
        if !self.active.contains(from) {
            return;
        }
        self.votes.insert(from);
        self.check_election();
    }

    pub(super) fn on_pre_vote(
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
            // A member whose deadline lapsed hears its leader at once.
            if self.role == Role::Leader && self.active.contains(from) {
                let round = self.leading.as_ref().map_or(0, |leading| leading.round);
                self.heartbeat_to(from, round);
            }
            return;
        }
        if let Some(heard) = self.last_heard_leader
            && self.now < heard + self.cfg.election_timeout_ms.0
            && self.seen_leader != Some(from)
        {
            self.send(from, refuse);
            return;
        }
        let up_to_date = self.log_reached(last_index, last_term);
        self.send(
            from,
            Message::PreVoteAnswer {
                term: self.term,
                next_term,
                granted: up_to_date,
            },
        );
    }

    pub(super) fn on_pre_vote_answer(&mut self, from: N, term: u64, next_term: u64, granted: bool) {
        if term > self.term {
            self.adopt_term(term);
            return;
        }
        if self.role != Role::PreCandidate || next_term != self.term + 1 || !granted {
            return;
        }
        if !self.active.contains(from) {
            return;
        }
        self.votes.insert(from);
        if self
            .active
            .quorum_holds(|member| self.votes.contains(&member))
        {
            self.pre_candidate_misses = 0;
            self.start_election();
        }
    }

    /// Hand leadership to `to`, or to the most up-to-date member.
    pub fn transfer_leadership(&mut self, to: Option<N>) {
        if self.role != Role::Leader {
            return;
        }
        let me = self.cfg.me;
        let target = to.or_else(|| {
            let leading = self.leading.as_ref()?;
            self.active
                .current
                .iter()
                .copied()
                .filter(|member| *member != me)
                .max_by_key(|&member| leading.matched(member))
        });
        let Some(target) = target else {
            return;
        };
        if target == me || !self.active.contains(target) {
            return;
        }
        let deadline = self.now + self.cfg.election_timeout_ms.1;
        if let Some(leading) = self.leading.as_mut() {
            leading.transfer = Some((target, deadline));
        }
        self.maybe_send_timeout_now();
        self.replicate_to(target);
    }

    pub(super) fn on_timeout_now(&mut self, from: N, term: u64) {
        if term == self.term
            && self.role == Role::Follower
            && self.seen_leader == Some(from)
            && !self.writer_stalled
            && self.is_member()
        {
            self.start_election();
        }
    }

    pub(super) fn transferring(&self) -> bool {
        self.leading
            .as_ref()
            .is_some_and(|leading| leading.transfer.is_some())
    }

    pub(super) fn maybe_send_timeout_now(&mut self) {
        let Some(leading) = self.leading.as_ref() else {
            return;
        };
        let Some((target, _)) = leading.transfer else {
            return;
        };
        // The target holding every entry is what makes the handover safe;
        // the leader's own durability is not needed, which lets a leader
        // whose writer stalled hand over.
        if leading.matched(target) >= self.log.last_index() {
            let term = self.term;
            self.send(target, Message::TimeoutNow { term });
        }
    }
}
