//! A simulated network between nodes, for any payload.

use alloc::collections::{BTreeMap, BTreeSet, BinaryHeap};
use core::cmp::Reverse;

use super::Random;

/// What the network does to messages.
#[derive(Debug, Clone, Copy)]
pub struct Faults {
    pub drop_per_million: u64,
    pub duplicate_per_million: u64,
    /// Delivery takes this many milliseconds, uniformly.
    pub delay: (u64, u64),
}

impl Default for Faults {
    fn default() -> Self {
        Self {
            drop_per_million: 0,
            duplicate_per_million: 0,
            delay: (1, 1),
        }
    }
}

/// A simulated network between nodes, for any payload.
pub struct Network<N: Ord + Copy, P> {
    faults: Faults,
    in_flight: BinaryHeap<Reverse<(u64, u64, N, N)>>,
    payloads: BTreeMap<u64, P>,
    next: u64,
    cut: BTreeSet<(N, N)>,
}

impl<N: Ord + Copy, P: Clone> Network<N, P> {
    pub fn new(faults: Faults) -> Self {
        Self {
            faults,
            in_flight: BinaryHeap::new(),
            payloads: BTreeMap::new(),
            next: 0,
            cut: BTreeSet::new(),
        }
    }

    pub fn set_faults(&mut self, faults: Faults) {
        self.faults = faults;
    }

    /// Queue `payload` from `from` to `to` at time `now`.
    pub fn send(&mut self, random: &mut Random, now: u64, from: N, to: N, payload: P) {
        if self.cut.contains(&(from, to)) || random.chance(self.faults.drop_per_million) {
            return;
        }
        let copies = if random.chance(self.faults.duplicate_per_million) {
            2
        } else {
            1
        };
        for _ in 0..copies {
            let at = now + random.between(self.faults.delay.0, self.faults.delay.1);
            self.next += 1;
            self.payloads.insert(self.next, payload.clone());
            self.in_flight.push(Reverse((at, self.next, from, to)));
        }
    }

    /// The next delivery due at or before `now`.
    pub fn deliver(&mut self, now: u64) -> Option<(N, N, P)> {
        loop {
            let Reverse((at, _, _, _)) = *self.in_flight.peek()?;
            if at > now {
                return None;
            }
            let Reverse((_, id, from, to)) = self.in_flight.pop().expect("peeked");
            let payload = self.payloads.remove(&id).expect("queued with its payload");
            // A partition made after sending still stops the message.
            if !self.cut.contains(&(from, to)) {
                return Some((from, to, payload));
            }
        }
    }

    /// When the next message is due.
    pub fn next_due(&self) -> Option<u64> {
        self.in_flight.peek().map(|Reverse((at, ..))| *at)
    }

    /// Stop messages from `from` to `to`.
    pub fn cut(&mut self, from: N, to: N) {
        self.cut.insert((from, to));
    }

    /// Separate `group` from everyone else, both ways.
    pub fn isolate(&mut self, group: &[N], all: &[N]) {
        for &inside in group {
            for &other in all {
                if !group.contains(&other) {
                    self.cut.insert((inside, other));
                    self.cut.insert((other, inside));
                }
            }
        }
    }

    pub fn heal(&mut self) {
        self.cut.clear();
    }
}
