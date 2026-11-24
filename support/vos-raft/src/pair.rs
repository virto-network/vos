//! The pair heartbeat, as one node tells it and another hears it. Each
//! node tells every other, once per interval, which groups it leads and at
//! what term. A round carries what changed since the last round its peer
//! took whole ([`Telling`]), so an idle node's rounds are empty, and the
//! peer keeps the listing in a [`PeerTable`]. A host vouches with the
//! table for a group's leader and members ([`crate::core::Core::vouch`])
//! before the group's own timers lapse. An idle group then sends nothing
//! ([`crate::Config::idle_heartbeats`]), and whatever goes wrong with the
//! pair heartbeat leaves Raft's own timing in charge.
//!
//! The table holds facts, never events: a peer's listing is vouched for as
//! of the last round taken whole, and a group it stops listing is gone
//! from it.

use alloc::collections::{BTreeMap, BTreeSet, VecDeque};
use alloc::vec::Vec;

/// The most rounds a teller keeps the changes of while its peer takes
/// none whole: past them, its rounds list everything again.
const UNACKED: usize = 64;

/// One round of a listing for one peer: `leading` and `unlisted` change
/// the listing as of round `since`, the last the peer took whole, or, with
/// `since` 0, are the listing whole.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Round<G> {
    pub since: u64,
    /// Groups led, at their terms, in group order.
    pub leading: Vec<(G, u64)>,
    /// Groups no longer led, in group order.
    pub unlisted: Vec<G>,
}

/// What one node tells one peer of the groups it leads, round by round:
/// each round the changes since the last round the peer took whole, every
/// group changed in any round since named at its value now. A round lost
/// loses nothing, as the next names its changes again.
#[derive(Debug)]
pub struct Telling<G> {
    /// The listing as of the last round made, in group order.
    listed: Vec<(G, u64)>,
    /// The last round the peer took whole: 0 for none.
    acked: u64,
    /// Each round made since `acked`, and the groups it changed.
    rounds: VecDeque<(u64, Vec<G>)>,
    /// The last round whose changes were let go unacknowledged.
    dropped: u64,
}

impl<G> Default for Telling<G> {
    fn default() -> Self {
        Self {
            listed: Vec::new(),
            acked: 0,
            rounds: VecDeque::new(),
            dropped: 0,
        }
    }
}

impl<G: Ord + Copy> Telling<G> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Round `round`'s listing for the peer, past every round made before:
    /// `listed` the groups led now, at their terms, in group order.
    pub fn round(&mut self, round: u64, listed: Vec<(G, u64)>) -> Round<G> {
        let changed = changes(&self.listed, &listed);
        self.listed = listed;
        self.rounds.push_back((round, changed));
        if self.rounds.len() > UNACKED
            && let Some((oldest, _)) = self.rounds.pop_front()
        {
            self.dropped = oldest;
        }
        // Changes since the round the peer took, if every round after it
        // is kept; else the listing whole.
        if self.acked == 0 || self.acked < self.dropped {
            return self.whole();
        }
        let touched: BTreeSet<G> = self
            .rounds
            .iter()
            .flat_map(|(_, changed)| changed.iter().copied())
            .collect();
        if touched.len() > self.listed.len() {
            return self.whole();
        }
        let mut leading = Vec::new();
        let mut unlisted = Vec::new();
        for group in touched {
            match self.listed.binary_search_by(|(at, _)| at.cmp(&group)) {
                Ok(at) => leading.push(self.listed[at]),
                Err(_) => unlisted.push(group),
            }
        }
        Round {
            since: self.acked,
            leading,
            unlisted,
        }
    }

    fn whole(&self) -> Round<G> {
        Round {
            since: 0,
            leading: self.listed.clone(),
            unlisted: Vec::new(),
        }
    }

    /// The peer took round `round` whole: later rounds change its listing
    /// as of then.
    pub fn acked(&mut self, round: u64) {
        if round <= self.acked {
            return;
        }
        self.acked = round;
        while self.rounds.front().is_some_and(|(at, _)| *at <= round) {
            self.rounds.pop_front();
        }
    }

    /// The peer's listing is gone (it started a new run): rounds list
    /// everything until it takes one whole.
    pub fn reset(&mut self) {
        self.acked = 0;
    }
}

/// The groups whose term differs between `before` and `after`, both in
/// group order, a group absent from one counting as differing.
fn changes<G: Ord + Copy>(before: &[(G, u64)], after: &[(G, u64)]) -> Vec<G> {
    let mut changed = Vec::new();
    let (mut old, mut new) = (before.iter().peekable(), after.iter().peekable());
    loop {
        match (old.peek(), new.peek()) {
            (None, None) => return changed,
            (Some(&&(group, _)), None) => {
                changed.push(group);
                old.next();
            }
            (None, Some(&&(group, _))) => {
                changed.push(group);
                new.next();
            }
            (Some(&&(was, term_was)), Some(&&(is, term_is))) => match was.cmp(&is) {
                core::cmp::Ordering::Less => {
                    changed.push(was);
                    old.next();
                }
                core::cmp::Ordering::Greater => {
                    changed.push(is);
                    new.next();
                }
                core::cmp::Ordering::Equal => {
                    if term_was != term_is {
                        changed.push(is);
                    }
                    old.next();
                    new.next();
                }
            },
        }
    }
}

/// One frame of a peer's round: `part` of `parts`, in its run
/// `incarnation`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame<G> {
    pub incarnation: u64,
    pub round: u64,
    pub part: u32,
    pub parts: u32,
    pub listing: Round<G>,
}

/// What a frame taken says about its sender: whether it began a run not
/// heard before, when the sender was last heard, if ever, and the groups
/// whose listing it changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Heard<T, G> {
    pub new_run: bool,
    pub before: Option<T>,
    pub changed: Vec<G>,
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
    /// Each group it lists: the term it leads at, and the last round that
    /// named it.
    leading: BTreeMap<G, (u64, u64)>,
    /// The last round taken whole, and when.
    whole: Option<(u64, T)>,
    /// The round whose parts are arriving, and the next part due.
    taking: Option<(u64, u32)>,
}

impl<N: Ord + Copy, G: Ord, T: Ord + Copy> Default for PeerTable<N, G, T> {
    fn default() -> Self {
        Self {
            peers: BTreeMap::new(),
        }
    }
}

impl<N: Ord + Copy, G: Ord + Copy, T: Ord + Copy> PeerTable<N, G, T> {
    pub fn new() -> Self {
        Self::default()
    }

    /// A frame from `from`, heard at `now`. One older than the last taken
    /// from `from` is ignored, and `None`: a late frame must not vouch for
    /// what has changed since. A new run's first frame forgets what the
    /// old one listed. A frame's changes apply when they run from a round
    /// taken whole; once every part of its round has arrived, the round
    /// counts as taken whole then, and a listing whole drops every group
    /// it did not name.
    pub fn heard(&mut self, from: N, now: T, frame: Frame<G>) -> Option<Heard<T, G>> {
        let at = (frame.incarnation, frame.round);
        let mut cleared = Vec::new();
        let (new_run, before) = match self.peers.get_mut(&from) {
            Some(peer) => {
                if at < peer.last {
                    return None;
                }
                let new_run = frame.incarnation != peer.last.0;
                if new_run {
                    // Every group the last run listed is no longer listed.
                    cleared.extend(peer.leading.keys().copied());
                    peer.leading.clear();
                    peer.whole = None;
                    peer.taking = None;
                }
                let before = peer.heard;
                peer.last = at;
                peer.heard = peer.heard.max(now);
                (new_run, Some(before))
            }
            None => {
                self.peers.insert(
                    from,
                    Peer {
                        heard: now,
                        last: at,
                        leading: BTreeMap::new(),
                        whole: None,
                        taking: None,
                    },
                );
                (true, None)
            }
        };
        let peer = self.peers.get_mut(&from).expect("just taken");
        let Frame {
            round,
            part,
            parts,
            listing,
            ..
        } = frame;
        // Parts arrive in order: a round is whole once each has.
        let next = match peer.taking {
            _ if part == 0 => Some((round, 0)),
            Some((taking, due)) if taking == round => Some((round, due)),
            _ => None,
        };
        peer.taking = next
            .filter(|&(_, due)| due == part)
            .map(|(round, due)| (round, due + 1));
        let mut changed = cleared;
        let applies =
            listing.since == 0 || peer.whole.is_some_and(|(taken, _)| listing.since <= taken);
        if !applies {
            peer.taking = None;
        } else {
            for (group, term) in listing.leading {
                if peer
                    .leading
                    .insert(group, (term, round))
                    .map(|(was, _)| was)
                    != Some(term)
                {
                    changed.push(group);
                }
            }
            for group in listing.unlisted {
                if peer.leading.remove(&group).is_some() {
                    changed.push(group);
                }
            }
            if peer.taking == Some((round, parts)) {
                if listing.since == 0 {
                    peer.leading.retain(|group, (_, named)| {
                        let kept = *named == round;
                        if !kept {
                            changed.push(*group);
                        }
                        kept
                    });
                }
                peer.whole = Some((round, now));
                peer.taking = None;
            }
        }
        Some(Heard {
            new_run,
            before,
            changed,
        })
    }

    /// When `node` was last heard, if it ever was.
    pub fn heard_at(&self, node: N) -> Option<T> {
        self.peers.get(&node).map(|peer| peer.heard)
    }

    /// When `node` last listed `group` as led at `term`, by the last round
    /// taken whole, if it did.
    pub fn listed(&self, node: N, group: &G, term: u64) -> Option<T> {
        let peer = self.peers.get(&node)?;
        let (listed, _) = peer.leading.get(group)?;
        if *listed != term {
            return None;
        }
        peer.whole.map(|(_, at)| at)
    }

    /// When a round of `node`'s was last taken whole, if one was.
    pub fn renewed(&self, node: N) -> Option<T> {
        self.peers.get(&node)?.whole.map(|(_, at)| at)
    }

    /// The run of `node`'s heard and its last round taken whole: what this
    /// node acknowledges to it.
    pub fn taken(&self, node: N) -> Option<(u64, u64)> {
        let peer = self.peers.get(&node)?;
        peer.whole.map(|(round, _)| (peer.last.0, round))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::random::Random;
    use alloc::vec;

    fn frame(
        incarnation: u64,
        round: u64,
        (part, parts): (u32, u32),
        listing: Round<u32>,
    ) -> Frame<u32> {
        Frame {
            incarnation,
            round,
            part,
            parts,
            listing,
        }
    }

    fn whole(leading: &[(u32, u64)]) -> Round<u32> {
        Round {
            since: 0,
            leading: leading.to_vec(),
            unlisted: Vec::new(),
        }
    }

    #[test]
    fn a_late_frame_changes_nothing() {
        let mut table = PeerTable::<u8, u32, u64>::new();
        let heard = table.heard(2, 10, frame(5, 3, (0, 1), whole(&[(7, 4)])));
        assert_eq!(
            heard,
            Some(Heard {
                new_run: true,
                before: None,
                changed: vec![7]
            })
        );
        assert_eq!(
            table.heard(2, 20, frame(5, 2, (0, 1), whole(&[(8, 4)]))),
            None
        );
        assert_eq!(table.listed(2, &8, 4), None);
        assert_eq!(table.listed(2, &7, 4), Some(10));
        assert_eq!(table.listed(2, &7, 5), None, "another term");
        assert_eq!(table.heard_at(2), Some(10));
        assert_eq!(table.taken(2), Some((5, 3)));
    }

    #[test]
    fn a_round_counts_once_every_part_arrived() {
        let mut table = PeerTable::<u8, u32, u64>::new();
        table.heard(2, 10, frame(5, 1, (0, 2), whole(&[(7, 4)])));
        assert_eq!(table.listed(2, &7, 4), None, "a part of a round");
        assert_eq!(table.renewed(2), None);
        table.heard(2, 11, frame(5, 1, (1, 2), whole(&[(8, 4)])));
        assert_eq!(table.listed(2, &7, 4), Some(11));
        assert_eq!(table.listed(2, &8, 4), Some(11));
        // A part missed: the round is not taken whole, and vouches for
        // nothing new.
        table.heard(2, 20, frame(5, 2, (1, 2), whole(&[(8, 4)])));
        assert_eq!(table.renewed(2), Some(11));
        assert_eq!(table.taken(2), Some((5, 1)));
    }

    #[test]
    fn changes_apply_from_a_round_taken_whole() {
        let mut table = PeerTable::<u8, u32, u64>::new();
        table.heard(2, 10, frame(5, 1, (0, 1), whole(&[(7, 4), (8, 4)])));
        let changes = Round {
            since: 1,
            leading: vec![(8, 5), (9, 1)],
            unlisted: vec![7],
        };
        let heard = table.heard(2, 20, frame(5, 2, (0, 1), changes)).unwrap();
        assert_eq!(heard.changed, vec![8, 9, 7]);
        assert_eq!(table.listed(2, &7, 4), None);
        assert_eq!(table.listed(2, &8, 5), Some(20));
        assert_eq!(table.listed(2, &9, 1), Some(20));
        // Changes from a round this table never took are not applied, and
        // renew nothing.
        let unknown = Round {
            since: 3,
            leading: vec![(10, 1)],
            unlisted: Vec::new(),
        };
        let heard = table.heard(2, 30, frame(5, 4, (0, 1), unknown)).unwrap();
        assert!(heard.changed.is_empty());
        assert_eq!(table.listed(2, &10, 1), None);
        assert_eq!(table.renewed(2), Some(20));
        // A listing whole drops what it does not name.
        let heard = table
            .heard(2, 40, frame(5, 5, (0, 1), whole(&[(9, 1)])))
            .unwrap();
        assert_eq!(heard.changed, vec![8]);
        assert_eq!(table.listed(2, &8, 5), None);
        assert_eq!(table.listed(2, &9, 1), Some(40));
    }

    #[test]
    fn a_new_run_forgets_the_last_ones_listing() {
        let mut table = PeerTable::<u8, u32, u64>::new();
        table.heard(2, 10, frame(5, 9, (0, 1), whole(&[(7, 4)])));
        let heard = table.heard(
            2,
            30,
            frame(
                6,
                1,
                (0, 1),
                Round {
                    since: 9,
                    leading: Vec::new(),
                    unlisted: Vec::new(),
                },
            ),
        );
        assert_eq!(
            heard,
            Some(Heard {
                new_run: true,
                before: Some(10),
                changed: vec![7]
            }),
            "what the last run listed is no longer"
        );
        assert_eq!(table.listed(2, &7, 4), None);
        assert_eq!(table.taken(2), None, "nothing taken whole from the new run");
        assert_eq!(
            table.heard(2, 40, frame(5, 10, (0, 1), whole(&[(7, 4)]))),
            None,
            "the old run"
        );
    }

    #[test]
    fn a_teller_sends_what_changed_since_the_round_its_peer_took() {
        let mut telling = Telling::<u32>::new();
        assert_eq!(
            telling.round(1, vec![(1, 1), (2, 1), (3, 1)]),
            whole(&[(1, 1), (2, 1), (3, 1)])
        );
        assert_eq!(
            telling.round(2, vec![(1, 1), (2, 2), (3, 1)]).since,
            0,
            "nothing taken yet"
        );
        telling.acked(1);
        assert_eq!(
            telling.round(3, vec![(1, 1), (2, 2), (4, 1)]),
            Round {
                since: 1,
                leading: vec![(2, 2), (4, 1)],
                unlisted: vec![3],
            }
        );
        telling.acked(3);
        assert_eq!(
            telling.round(4, vec![(1, 1), (2, 2), (4, 1)]),
            Round {
                since: 3,
                leading: Vec::new(),
                unlisted: Vec::new(),
            },
            "idle: an empty round"
        );
        telling.reset();
        assert_eq!(telling.round(5, vec![(1, 1)]), whole(&[(1, 1)]));
    }

    #[test]
    fn a_teller_whose_peer_takes_nothing_lists_everything_again() {
        let mut telling = Telling::<u32>::new();
        telling.round(1, vec![(1, 1), (2, 1), (3, 1)]);
        telling.acked(1);
        for round in 2..=(UNACKED as u64 + 1) {
            assert_eq!(
                telling.round(round, vec![(1, 1), (2, 1), (3, round)]).since,
                1
            );
        }
        // The changes of round 2 are let go: round 1 no longer serves.
        let round = telling.round(UNACKED as u64 + 2, vec![(1, 1), (2, 1), (3, 1)]);
        assert_eq!(round.since, 0);
        assert_eq!(round.leading, vec![(1, 1), (2, 1), (3, 1)]);
    }

    /// A teller and a table over a link that loses, splits and delays
    /// frames, the acknowledgements late too: whenever the table takes a
    /// round whole, its listing is the teller's in that round.
    #[test]
    fn a_table_takes_the_tellers_listing_through_losses() {
        for seed in 1..=40 {
            let mut random = Random::new(seed);
            let mut telling = Telling::<u32>::new();
            let mut table = PeerTable::<u8, u32, u64>::new();
            let mut listing: BTreeMap<u32, u64> = BTreeMap::new();
            let mut sent: BTreeMap<u64, BTreeMap<u32, u64>> = BTreeMap::new();
            let mut acks: VecDeque<(u64, u64)> = VecDeque::new();
            let mut taken_rounds = 0;
            for round in 1..=300u64 {
                for _ in 0..random.between(0, 4) {
                    let group = random.between(0, 40) as u32;
                    if random.chance(300_000) {
                        listing.remove(&group);
                    } else {
                        listing.insert(group, random.between(1, 5));
                    }
                }
                let now: Vec<(u32, u64)> = listing.iter().map(|(g, t)| (*g, *t)).collect();
                sent.insert(round, listing.clone());
                let told = telling.round(round, now);
                // Split into parts of three entries at most.
                let mut parts: Vec<Round<u32>> = Vec::new();
                // Each entry a group listed, or one unlisted.
                type Entry = (Option<(u32, u64)>, Option<u32>);
                let entries: Vec<Entry> = told
                    .leading
                    .iter()
                    .map(|entry| (Some(*entry), None))
                    .chain(told.unlisted.iter().map(|group| (None, Some(*group))))
                    .collect();
                for chunk in entries.chunks(3) {
                    parts.push(Round {
                        since: told.since,
                        leading: chunk.iter().filter_map(|(entry, _)| *entry).collect(),
                        unlisted: chunk.iter().filter_map(|(_, group)| *group).collect(),
                    });
                }
                if parts.is_empty() {
                    parts.push(Round {
                        since: told.since,
                        leading: Vec::new(),
                        unlisted: Vec::new(),
                    });
                }
                let count = parts.len() as u32;
                for (part, listing) in parts.into_iter().enumerate() {
                    // Lose a part now and then: the rest of its round goes
                    // on, as a link that dropped one frame does.
                    if random.chance(150_000) {
                        continue;
                    }
                    let before = table.taken(2);
                    table.heard(2, round, frame(1, round, (part as u32, count), listing));
                    let after = table.taken(2);
                    if after != before
                        && let Some((_, whole)) = after
                    {
                        taken_rounds += 1;
                        let expected = &sent[&whole];
                        for group in 0..=40u32 {
                            let held = expected
                                .get(&group)
                                .and_then(|term| table.listed(2, &group, *term));
                            assert_eq!(
                                held.is_some(),
                                expected.contains_key(&group),
                                "seed {seed}, round {round}, group {group}"
                            );
                            for term in 1..=5 {
                                if Some(&term) != expected.get(&group) {
                                    assert_eq!(table.listed(2, &group, term), None);
                                }
                            }
                        }
                        acks.push_back((round + random.between(0, 3), whole));
                    }
                }
                while acks.front().is_some_and(|(due, _)| *due <= round) {
                    let (_, whole) = acks.pop_front().expect("checked");
                    if !random.chance(100_000) {
                        telling.acked(whole);
                    }
                }
            }
            assert!(
                taken_rounds > 100,
                "seed {seed}: {taken_rounds} rounds taken"
            );
        }
    }
}
