//! The blobs a group's entries, or the snapshot it stages, wait for:
//! asked of the leader first, then of each member in turn.

use std::collections::{BTreeSet, HashMap};
use std::time::{Duration, Instant};

use vos_wire::peer::{NodeNumber, PeerMessage};

use super::Driver;
use crate::blobs::Keep;

/// How long a group waits for blobs it asked for before asking again,
/// another member.
const BLOB_RETRY: Duration = Duration::from_secs(1);

/// The blobs a group asked for and still waits on, and the member it asks
/// next.
#[derive(Default)]
pub(super) struct Fetch {
    asks: Asks,
    /// Which member to ask next.
    turn: usize,
}

impl Fetch {
    /// When the longest wait comes to the retry interval.
    pub(super) fn due(&self) -> Option<Instant> {
        self.asks.due()
    }

    /// The next of `others` to ask.
    fn next_member(&mut self, others: &[NodeNumber]) -> NodeNumber {
        self.turn += 1;
        others[self.turn % others.len()]
    }
}

impl Driver {
    /// Ask for the blobs the group's entries, or the snapshot it stages,
    /// wait for: each new one of the leader, which stored any large result
    /// it proposed, and each one that waited [`BLOB_RETRY`] of the next
    /// member.
    ///
    /// The host never gives up on a blob (vos-raft's `discard_unreported`
    /// is never called). A restart's recovery cuts an entry missing its
    /// blob only above the commit it recovers ([`raft::recovery_cut`]); one
    /// at or below it is committed and never cut: past the applied index
    /// it is kept, its blobs fetched again, and recovery logs that it
    /// waits; at or below it, the log is compacted through the applied
    /// index. So a replica holding a committed entry whose blob no member
    /// still has waits for it for good, applying nothing past it. The
    /// trust model accepts that (core model, section 5): nodes may crash,
    /// and such a replica is one crashed, while the quorum goes on.
    pub(super) fn fetch_blobs(&mut self) {
        let mut missing: BTreeSet<[u8; 32]> = self.reports.missing().into_iter().collect();
        missing.extend(self.snapshots.missing.iter().copied());
        if missing.is_empty() {
            self.fetch.asks.clear();
            return;
        }
        if self.inner.network.is_none() {
            return;
        }
        let me = self.inner.number;
        let others: Vec<NodeNumber> = self
            .inner
            .placement(self.shared.agent)
            .map(|placement| placement.replicas)
            .unwrap_or_default()
            .into_iter()
            .filter(|node| *node != me)
            .collect();
        if others.is_empty() {
            return;
        }
        let ask = self.fetch.asks.next(&missing, Instant::now());
        let leader = self.shared.state().leader.filter(|leader| *leader != me);
        if !ask.fresh.is_empty() {
            let to = leader.unwrap_or_else(|| self.fetch.next_member(&others));
            self.ask(to, ask.fresh);
        }
        if !ask.retry.is_empty() {
            let to = self.fetch.next_member(&others);
            self.ask(to, ask.retry);
        }
    }

    /// Ask node `to` for `hashes`. A program a staged snapshot waits for is
    /// kept by its age until the switch pins it; every other blob, by the
    /// entry naming it.
    fn ask(&self, to: NodeNumber, hashes: Vec<[u8; 32]>) {
        let (aged, named): (Vec<[u8; 32]>, Vec<[u8; 32]>) = hashes
            .iter()
            .partition(|hash| self.snapshots.missing.contains(hash));
        self.inner.want(self.shared.agent, &aged, Keep::Aged);
        self.inner.want(self.shared.agent, &named, Keep::Named);
        let agent = self.shared.agent;
        self.inner
            .send(to, &PeerMessage::BlobRequest { agent, hashes });
    }
}

/// The blobs a group asked for and still waits on, each with when it was
/// last asked.
#[derive(Default)]
struct Asks(HashMap<[u8; 32], Instant>);

/// What a group asks for in one round.
#[derive(Debug, Default, PartialEq, Eq)]
struct Ask {
    /// The blobs not asked for yet: of the leader.
    fresh: Vec<[u8; 32]>,
    /// The blobs that waited the retry interval since they were last asked
    /// for: of the next member.
    retry: Vec<[u8; 32]>,
}

impl Asks {
    /// Of `missing`, what to ask for at `now`, noted as asked then. A blob
    /// is asked for again only once it waited [`BLOB_RETRY`]: one asked a
    /// moment ago is not asked again of a member the turn comes back to.
    fn next(&mut self, missing: &BTreeSet<[u8; 32]>, now: Instant) -> Ask {
        self.0.retain(|hash, _| missing.contains(hash));
        let mut ask = Ask::default();
        for hash in missing {
            match self.0.get(hash) {
                None => ask.fresh.push(*hash),
                Some(at) if now.saturating_duration_since(*at) >= BLOB_RETRY => {
                    ask.retry.push(*hash)
                }
                Some(_) => {}
            }
        }
        for hash in ask.fresh.iter().chain(&ask.retry) {
            self.0.insert(*hash, now);
        }
        ask
    }

    /// When the longest wait comes to the retry interval.
    fn due(&self) -> Option<Instant> {
        self.0.values().min().map(|at| *at + BLOB_RETRY)
    }

    fn clear(&mut self) {
        self.0.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set(hashes: &[u8]) -> BTreeSet<[u8; 32]> {
        hashes.iter().map(|byte| [*byte; 32]).collect()
    }

    fn ask(fresh: &[u8], retry: &[u8]) -> Ask {
        let hashes = |bytes: &[u8]| bytes.iter().map(|byte| [*byte; 32]).collect();
        Ask {
            fresh: hashes(fresh),
            retry: hashes(retry),
        }
    }

    /// A fresh ask carries only the blobs not asked for yet; a blob asked
    /// for is asked again only once it waited the retry interval.
    #[test]
    fn a_blob_is_asked_for_once_until_a_retry() {
        let start = Instant::now();
        let at = |millis: u64| start + Duration::from_millis(millis);
        let mut asks = Asks::default();
        assert_eq!(asks.next(&set(&[1, 2]), at(0)), ask(&[1, 2], &[]));
        assert_eq!(asks.next(&set(&[1, 2]), at(100)), ask(&[], &[]));
        assert_eq!(asks.next(&set(&[1, 2, 3]), at(200)), ask(&[3], &[]));
        assert_eq!(asks.due(), Some(at(0) + BLOB_RETRY));
        // 1 and 2 arrived: 3 waits from its own ask.
        assert_eq!(asks.next(&set(&[3, 4]), at(1_000)), ask(&[4], &[]));
        assert_eq!(asks.due(), Some(at(200) + BLOB_RETRY));
        assert_eq!(asks.next(&set(&[3, 4]), at(1_100)), ask(&[], &[]));
        assert_eq!(asks.next(&set(&[3, 4, 5]), at(1_200)), ask(&[5], &[3]));
        assert_eq!(asks.due(), Some(at(1_000) + BLOB_RETRY));
        assert_eq!(asks.next(&set(&[3, 4, 5]), at(2_000)), ask(&[], &[4]));
        // A blob that arrived and is missing again is new.
        assert_eq!(asks.next(&set(&[4]), at(2_100)), ask(&[], &[]));
        assert_eq!(asks.next(&set(&[3, 4]), at(2_200)), ask(&[3], &[]));
        asks.clear();
        assert_eq!(asks.due(), None);
    }
}
