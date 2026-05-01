//! Cluster role for a Raft replication group.
//!
//! Pure data — no atomics, no locking. The worker (added in a
//! later commit) holds a `Role` value as part of its state and
//! mirrors it into a shared atomic for lock-free external reads.

/// Where this replica currently sits in the Raft consensus
/// lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Role {
    /// Following the cluster's leader. Responds to AppendEntries
    /// and RequestVote; will start a new election if no
    /// heartbeat arrives within the election timeout.
    Follower,
    /// Soliciting votes for an election we started. Stays here
    /// until we either gather a quorum (→ Leader) or observe a
    /// higher term (→ Follower).
    Candidate,
    /// Authoritative for the current term. Replicates entries
    /// to followers and emits heartbeats to keep their election
    /// timers reset.
    Leader,
}

impl Role {
    /// 8-bit encoding for atomic mirrors. The worker exposes its
    /// current role through a shared `AtomicU8` so external
    /// readers (e.g. a `CommitStrategy::is_writable` check) can
    /// read leader-vs-follower without bouncing through the
    /// worker's mailbox.
    pub fn as_u8(self) -> u8 {
        match self {
            Self::Follower => 0,
            Self::Candidate => 1,
            Self::Leader => 2,
        }
    }

    /// Inverse of [`Self::as_u8`]. Out-of-range values (which
    /// can't happen if the producer also uses `as_u8`) decode
    /// as `Follower` — the safe default.
    pub fn from_u8(v: u8) -> Self {
        match v {
            1 => Self::Candidate,
            2 => Self::Leader,
            _ => Self::Follower,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_round_trips_through_u8() {
        for r in [Role::Follower, Role::Candidate, Role::Leader] {
            assert_eq!(Role::from_u8(r.as_u8()), r);
        }
    }

    #[test]
    fn unknown_u8_decodes_as_follower() {
        assert_eq!(Role::from_u8(255), Role::Follower);
    }
}
