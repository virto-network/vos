//! What a host schedules around the core: campaigns it bounds, and the
//! pair heartbeat that stands in for an idle group's timers.

use alloc::collections::BTreeSet;

use super::Core;
use crate::config::NodeId;
use crate::role::Role;

impl<N: NodeId> Core<N> {
    /// Whether a tick at `now` would start a campaign, or a campaign's
    /// next round: a member that does not lead, can write, holds the log it
    /// held before any wipe, and whose election deadline is due.
    pub fn campaign_due(&self, now: u64) -> bool {
        self.role != Role::Leader
            && now.max(self.now) >= self.election_deadline
            && self.is_member()
            && !self.writer_stalled
            && !self.short_of_floor()
            && self.term < u64::MAX
    }

    /// Put off a campaign due at `now` until `until`: a host that bounds
    /// the campaigns its groups run at once defers the others, and starts
    /// each again as one ends ([`Self::campaign_now`]).
    pub fn defer_campaign(&mut self, now: u64, until: u64) {
        self.now = self.now.max(now);
        if self.role != Role::Leader {
            self.election_deadline = until.max(self.now);
        }
    }

    /// A campaign put off may start at `now`: its election deadline comes
    /// due then, unless it heard a leader since within the election
    /// timeout's lower end.
    pub fn campaign_now(&mut self, now: u64) {
        self.now = self.now.max(now);
        if self.role != Role::Leader && !self.leader_heard_within(0) {
            self.election_deadline = self.election_deadline.min(self.now);
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
        if self.role == Role::Follower {
            if let Some(leader) = self.seen_leader
                && let Some(at) = listed(leader, self.term)
                && at + low > self.now
            {
                self.heard_leader_at(at);
            }
            return;
        }
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
        for member in self.active.others(me) {
            if heard(member).is_none_or(|at| at + high <= now) {
                silent.insert(member);
            } else if leading.peers.get(&member).is_some_and(|progress| {
                progress.matched >= last || progress.answered + patience > now
            }) {
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
        for (peer, progress) in &mut leading.peers {
            progress.silent = silent.contains(peer);
        }
    }

    /// Whether the core's only deadline is one the host's pair heartbeat
    /// stands in for: a follower's election timer while its leader was
    /// vouched for more than `margin` before its stickiness lapses, or an
    /// idle leader's check-quorum while every member's node is heard and
    /// holds every entry and the commit. The host may then stop ticking it
    /// until a message comes, its leader stops listing the group at its
    /// term, or a member's node falls silent, provided it notices either
    /// within `margin`; it vouches before the tick it then gives
    /// ([`Self::vouch`]).
    pub fn quiescent(&self, margin: u64) -> bool {
        if !self.reads.is_empty() || self.writer_stalled || !self.is_member() {
            return false;
        }
        match self.role {
            Role::Follower => {
                self.seen_leader.is_some_and(|leader| leader != self.cfg.me)
                    && self.leader_heard_within(margin)
            }
            Role::Leader => self.leading.as_ref().is_some_and(|leading| {
                self.election_deadline == u64::MAX
                    && leading.transfer.is_none()
                    && leading.peers.values().all(|progress| {
                        !progress.silent
                            && progress.in_flight.is_none()
                            && progress.snapshotting.is_none()
                            && !progress.loading
                    })
            }),
            Role::PreCandidate | Role::Candidate => false,
        }
    }

    /// The host ticks a quiescent core again after a wait, at `now`: a
    /// leader whose check-quorum came due meanwhile counts as heard only
    /// the members heard since, which the host's vouch that follows adds,
    /// not those heard before the wait.
    pub fn resume(&mut self, now: u64) {
        self.now = self.now.max(now);
        if let Some(leading) = self.leading.as_mut()
            && self.now >= leading.check_quorum_due
        {
            leading.recent.clear();
        }
    }

    /// `node` came back (a new run of it, or heard again after a silence):
    /// a leader no longer counts it as caught up, and sends it a heartbeat
    /// at once, so a replica that restarted learns its leader and the
    /// commit without waiting for its own deadline.
    pub fn probe(&mut self, node: N) {
        if node == self.cfg.me {
            return;
        }
        let Some(leading) = self.leading.as_mut() else {
            return;
        };
        if let Some(progress) = leading.peers.get_mut(&node) {
            progress.acked_commit = 0;
            progress.silent = false;
        }
        let round = leading.round;
        if self.active.contains(node) {
            self.heartbeat_to(node, round);
        }
    }
}
