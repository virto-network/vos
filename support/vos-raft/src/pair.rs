//! The pair heartbeat, as one node hears it. Each node tells every other,
//! once per interval, which groups it leads and at what term; a host keeps
//! what it heard in a [`PeerTable`], and vouches with it for a group's
//! leader and members ([`crate::core::Core::vouch`]) before the group's own
//! timers lapse. An idle group then sends nothing
//! ([`crate::Config::idle_heartbeats`]), and whatever goes wrong with the
//! pair heartbeat leaves Raft's own timing in charge.
//!
//! The table holds facts, never events: a group a peer stops listing
//! simply ages out of the window a vouch accepts.

use alloc::collections::BTreeMap;

/// What a pair heartbeat taken says about its sender: whether it began a
/// run not heard before, and when the sender was last heard, if ever.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Heard<T> {
    pub new_run: bool,
    pub before: Option<T>,
}

/// What one node heard from each peer's pair heartbeats: `N` names nodes,
/// `G` groups, and `T` is the host's clock.
#[derive(Debug)]
pub struct PeerTable<N, G, T> {
    peers: BTreeMap<N, Peer<G, T>>,
}

#[derive(Debug)]
struct Peer<G, T> {
    /// When it was last heard.
    heard: T,
    /// The latest `(incarnation, round)` taken from it.
    last: (u64, u64),
    /// Each group it listed: the term it leads at, and when it last
    /// listed it.
    leading: BTreeMap<G, (u64, T)>,
}

impl<N: Ord + Copy, G: Ord, T: Ord + Copy> Default for PeerTable<N, G, T> {
    fn default() -> Self {
        Self {
            peers: BTreeMap::new(),
        }
    }
}

impl<N: Ord + Copy, G: Ord, T: Ord + Copy> PeerTable<N, G, T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// A pair heartbeat, or one part of it, from `from` in its run
    /// `incarnation` and round `round`, listing the groups it leads with
    /// their terms, heard at `now`. One older than the last taken from
    /// `from` is ignored, and `None`: a late frame must not vouch for what
    /// has changed since. A new run's first heartbeat forgets what the old
    /// one listed. One taken says whether it began a new run, and when its
    /// sender was heard before.
    pub fn heard(
        &mut self,
        from: N,
        now: T,
        incarnation: u64,
        round: u64,
        leading: impl IntoIterator<Item = (G, u64)>,
    ) -> Option<Heard<T>> {
        let heard = match self.peers.get_mut(&from) {
            Some(peer) => {
                if (incarnation, round) < peer.last {
                    return None;
                }
                let heard = Heard {
                    new_run: incarnation != peer.last.0,
                    before: Some(peer.heard),
                };
                if heard.new_run {
                    peer.leading.clear();
                }
                peer.last = (incarnation, round);
                peer.heard = peer.heard.max(now);
                heard
            }
            None => {
                self.peers.insert(
                    from,
                    Peer {
                        heard: now,
                        last: (incarnation, round),
                        leading: BTreeMap::new(),
                    },
                );
                Heard {
                    new_run: true,
                    before: None,
                }
            }
        };
        let peer = self.peers.get_mut(&from).expect("just taken");
        for (group, term) in leading {
            peer.leading.insert(group, (term, now));
        }
        Some(heard)
    }

    /// When `node` was last heard, if it ever was.
    pub fn heard_at(&self, node: N) -> Option<T> {
        self.peers.get(&node).map(|peer| peer.heard)
    }

    /// When `node` last listed `group` as led at `term`, if it did.
    pub fn listed(&self, node: N, group: &G, term: u64) -> Option<T> {
        let (listed, at) = self.peers.get(&node)?.leading.get(group)?;
        (*listed == term).then_some(*at)
    }

    /// Forget each listing older than `before`, so a table over groups
    /// that come and go stays bounded.
    pub fn forget_before(&mut self, before: T) {
        for peer in self.peers.values_mut() {
            peer.leading.retain(|_, (_, at)| *at >= before);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_late_heartbeat_changes_nothing() {
        let mut table = PeerTable::<u8, u32, u64>::new();
        assert_eq!(
            table.heard(2, 10, 5, 3, [(7, 4)]),
            Some(Heard {
                new_run: true,
                before: None
            })
        );
        assert_eq!(table.heard(2, 20, 5, 2, [(8, 4)]), None, "an older round");
        assert_eq!(table.listed(2, &8, 4), None);
        // Another frame of the same round adds to its list.
        assert!(table.heard(2, 20, 5, 3, [(8, 4)]).is_some());
        assert_eq!(table.listed(2, &7, 4), Some(10));
        assert_eq!(table.listed(2, &8, 4), Some(20));
        assert_eq!(table.listed(2, &8, 5), None, "another term");
        assert_eq!(table.heard_at(2), Some(20));
    }

    #[test]
    fn a_new_run_forgets_the_last_ones_list() {
        let mut table = PeerTable::<u8, u32, u64>::new();
        table.heard(2, 10, 5, 9, [(7, 4)]);
        let heard = table.heard(2, 30, 6, 1, []).unwrap();
        assert_eq!(
            heard,
            Heard {
                new_run: true,
                before: Some(10)
            }
        );
        assert_eq!(table.listed(2, &7, 4), None);
        assert_eq!(table.heard(2, 40, 5, 10, [(7, 4)]), None, "the old run");
    }

    #[test]
    fn listings_not_renewed_are_forgotten() {
        let mut table = PeerTable::<u8, u32, u64>::new();
        table.heard(2, 10, 5, 1, [(7, 4)]);
        table.heard(2, 50, 5, 2, [(8, 4)]);
        table.forget_before(30);
        assert_eq!(table.listed(2, &7, 4), None);
        assert_eq!(table.listed(2, &8, 4), Some(50));
    }
}
