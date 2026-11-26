//! A replica's role in a Raft group.

/// Where this replica currently sits in the Raft consensus
/// lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Following the group's leader. Answers appends and vote
    /// requests; starts a campaign if no append arrives within the
    /// election timeout.
    Follower,
    /// Sending pre-votes to gauge whether a real election
    /// would succeed at `current_term + 1`. Has not yet bumped
    /// `current_term` or persisted a self-vote. Transitions to
    /// `Candidate` on quorum of yes-replies, or back to
    /// `Follower` on a higher-term response or after
    /// `pre_candidate_misses_before_revert` rounds without a quorum.
    PreCandidate,
    /// Asking for votes in a real election. Its term was bumped and
    /// its self-vote written; the requests leave once both are
    /// durable. Stays here until it gathers a quorum (→ Leader) or
    /// observes a higher term (→ Follower).
    Candidate,
    /// Authoritative for the current term. Replicates entries
    /// to followers and sends heartbeats to keep their election
    /// timers reset.
    Leader,
}
