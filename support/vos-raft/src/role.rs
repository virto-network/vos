//! A replica's role in a Raft group.

/// Where this replica currently sits in the Raft consensus
/// lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Following the cluster's leader. Responds to AppendEntries
    /// and RequestVote; will start a new election if no
    /// heartbeat arrives within the election timeout.
    Follower,
    /// Sending PreVote RPCs to gauge whether a real election
    /// would succeed at `current_term + 1`. Has NOT yet bumped
    /// `current_term` or persisted a self-vote. Transitions to
    /// `Candidate` on quorum of yes-replies, or back to
    /// `Follower` on a higher-term response or after
    /// `pre_candidate_misses_before_revert` rounds without a quorum.
    PreCandidate,
    /// Soliciting votes for a real election. Term has been
    /// bumped, self-vote persisted. Stays here until we either
    /// gather a quorum (→ Leader) or observe a higher term
    /// (→ Follower).
    Candidate,
    /// Authoritative for the current term. Replicates entries
    /// to followers and emits heartbeats to keep their election
    /// timers reset.
    Leader,
}
