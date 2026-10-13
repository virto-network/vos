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

impl Role {
    /// 8-bit encoding, for the thread-per-group driver's atomic
    /// mirror of its role.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Follower => 0,
            Self::Candidate => 1,
            Self::Leader => 2,
            Self::PreCandidate => 3,
        }
    }

    /// Inverse of [`Self::as_u8`]. Out-of-range values (which
    /// can't happen if the producer also uses `as_u8`) decode
    /// as `Follower` — the safe default.
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Candidate,
            2 => Self::Leader,
            3 => Self::PreCandidate,
            _ => Self::Follower,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_round_trips_through_u8() {
        for r in [
            Role::Follower,
            Role::PreCandidate,
            Role::Candidate,
            Role::Leader,
        ] {
            assert_eq!(Role::from_u8(r.as_u8()), r);
        }
    }

    #[test]
    fn unknown_u8_decodes_as_follower() {
        assert_eq!(Role::from_u8(255), Role::Follower);
    }
}
