//! Per-replica configuration for one Raft group.
//!
//! Pure data, parameterized over the `NodeId` type so embedded
//! consumers can use a `u8` or `u16` while large clusters can use
//! `[u8; 32]` or a custom newtype.

use alloc::vec::Vec;
use core::fmt::Debug;
use core::hash::Hash;

/// Identity type for cluster members. Must be cheap to copy +
/// compare + hash. The bound list is intentionally minimal so
/// embedded targets can use a primitive (u8 / u16 / u32) without
/// extra ceremony.
pub trait NodeId: Copy + Eq + Ord + Hash + Debug + Send + Sync + 'static {}
impl<T> NodeId for T where T: Copy + Eq + Ord + Hash + Debug + Send + Sync + 'static {}

/// Per-replica configuration. Every field is pure data; nothing
/// here resolves peers, opens databases, or contacts the network.
/// The worker consumes a `Config` once at construction.
///
/// Marked `#[non_exhaustive]` so additional tuning knobs can land
/// in minor versions without breaking SemVer. Construct via
/// `Config { ..Default::default() }` or with explicit field
/// initialization plus the leading `..` rest pattern.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Config<N: NodeId> {
    /// This replica's identity. Has to appear in `members`.
    pub me: N,
    /// Static cluster membership. Empty / one-element disables
    /// elections — the lone member self-votes and immediately
    /// becomes leader. Replicas of the same group must list the
    /// same set in the same order.
    pub members: Vec<N>,
    /// Randomized election-timeout window (low, high) in
    /// milliseconds. The actual timeout for each Follower /
    /// Candidate cycle is drawn uniformly from this range. Tests
    /// shrink to ~50ms; production defaults sit at 150-300ms.
    pub election_timeout_ms: (u64, u64),
    /// Leader heartbeat interval in milliseconds. Should be
    /// substantially smaller than `election_timeout_ms.0` so
    /// followers always see a heartbeat before timing out.
    /// Standard Raft guidance: ~10× smaller.
    pub heartbeat_interval_ms: u64,
    /// Replication group ID — used as a routing key when a
    /// transport multiplexes multiple Raft groups over one
    /// physical channel (e.g. libp2p with several actors). The
    /// worker doesn't interpret this; it just hands it to the
    /// transport.
    pub replication_id: [u8; 32],
}

impl<N: NodeId> Config<N> {
    /// Construct with sensible defaults for everything except the
    /// caller-required fields. Election timeouts default to
    /// 150–300ms and the heartbeat interval to 50ms — Raft's
    /// "10× smaller" guidance with margin.
    pub fn new(me: N, members: Vec<N>, replication_id: [u8; 32]) -> Self {
        Self {
            me,
            members,
            election_timeout_ms: (150, 300),
            heartbeat_interval_ms: 50,
            replication_id,
        }
    }
}

impl<N: NodeId> Config<N> {
    /// Quorum size: majority of total members, with the
    /// candidate's own self-vote counted. For 3 members → 2
    /// votes; 5 → 3; etc. A single-member configuration's
    /// quorum is 1 (self-vote alone).
    pub fn quorum(&self) -> usize {
        self.members.len() / 2 + 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec;

    fn cfg(members: Vec<u16>) -> Config<u16> {
        Config::new(members[0], members, [0u8; 32])
    }

    #[test]
    fn quorum_matches_raft_majority_rule() {
        assert_eq!(cfg(vec![0xA]).quorum(), 1);
        assert_eq!(cfg(vec![0xA, 0xB]).quorum(), 2);
        assert_eq!(cfg(vec![0xA, 0xB, 0xC]).quorum(), 2);
        assert_eq!(cfg(vec![0xA, 0xB, 0xC, 0xD, 0xE]).quorum(), 3);
        assert_eq!(cfg((0..7).collect()).quorum(), 4);
    }
}
