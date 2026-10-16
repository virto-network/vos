//! What this leadership sent each target past its acknowledgement, and
//! when it sends it again.

use std::collections::VecDeque;
use std::time::{Duration, Instant};

/// What a sender sends a target past the target's acknowledgement at
/// once: entries, and bytes, at least one entry.
pub(super) const WINDOW: usize = 256;
const WINDOW_BYTES: usize = 1 << 20;
/// A round's wait doubles up to this many times its first: the node's
/// `resend_round`.
const MAX_ROUNDS: u32 = 16;
/// How often a receiver's `Behind` may send a target's window again.
pub(super) const BEHIND_EVERY: Duration = Duration::from_millis(100);

/// What this leadership sent a target past its acknowledgement.
pub(super) struct Window {
    /// The highest acknowledgement taken, from the queue or applied.
    acked: u64,
    /// The last sequence the outbox holds for the target, as last read.
    last: u64,
    /// The sequences sent past `acked`, with their sizes.
    sent: VecDeque<(u64, usize)>,
    bytes: usize,
    /// When the acknowledgement last moved, or the window last went again.
    since: Instant,
    /// How long after `since` it goes again.
    wait: Duration,
    /// The first wait, to which an acknowledgement brings it back.
    round: Duration,
    /// Which replica of the target it goes through, when it goes through
    /// one: the same for a whole window, another each round.
    turn: u64,
    /// When a receiver's `Behind` last sent it again.
    behind: Option<Instant>,
    /// A `Behind` came too soon after that, when the window had sent
    /// through this sequence: it rewinds once [`BEHIND_EVERY`] has passed,
    /// unless an acknowledgement reaches the sequence first. A receiver can
    /// only have dropped or refused what it was sent before its `Behind`;
    /// what the window sends past the sequence goes on from each
    /// acknowledgement, and its drops bring a `Behind` of their own.
    deferred: Option<u64>,
}

impl Window {
    /// A window from `acked` on, through the replica `turn` picks first,
    /// each node starting at its own so senders spread over the replicas,
    /// going again after `round` while its acknowledgement stays behind.
    pub(super) fn new(acked: u64, turn: u64, round: Duration) -> Self {
        Self {
            acked,
            last: acked,
            sent: VecDeque::new(),
            bytes: 0,
            since: Instant::now(),
            wait: round,
            round,
            turn,
            behind: None,
            deferred: None,
        }
    }

    /// The outbox holds the target's messages through `last`.
    pub(super) fn holds(&mut self, last: u64) {
        self.last = self.last.max(last);
    }

    /// Whether all the outbox holds, as last read, was sent or acknowledged.
    pub(super) fn sent_all(&self) -> bool {
        self.through() >= self.last
    }

    /// `sequence`, of `size`, sent past the acknowledgement.
    pub(super) fn push(&mut self, sequence: u64, size: usize) {
        self.sent.push_back((sequence, size));
        self.bytes += size;
    }

    /// Whether the target acknowledged all the outbox holds for it, as
    /// last read, and nothing waits for an acknowledgement.
    pub(super) fn idle(&self) -> bool {
        self.last <= self.acked && self.sent.is_empty()
    }

    /// The replica of the target it goes through.
    pub(super) fn turn(&self) -> u64 {
        self.turn
    }

    /// The last sequence sent, or acknowledged.
    pub(super) fn through(&self) -> u64 {
        self.sent
            .back()
            .map_or(self.acked, |(sequence, _)| *sequence)
    }

    pub(super) fn ack(&mut self, sequence: u64) {
        if sequence <= self.acked {
            return;
        }
        self.acked = sequence;
        while let Some((sent, size)) = self.sent.front().copied() {
            if sent > sequence {
                break;
            }
            self.sent.pop_front();
            self.bytes -= size;
        }
        // An acknowledgement short of what was sent when a deferred
        // `Behind` came keeps it: the receiver tells a sender of drops at a
        // full queue once, and the acknowledgement may be older than the
        // `Behind`, taken in a batch after it arrived.
        if self.deferred.is_some_and(|through| sequence >= through) {
            self.deferred = None;
        }
        self.since = Instant::now();
        self.wait = self.round;
    }

    pub(super) fn full(&self, size: usize) -> bool {
        self.sent.len() >= WINDOW || (!self.sent.is_empty() && self.bytes + size > WINDOW_BYTES)
    }

    /// When it goes again, while the outbox holds more than was
    /// acknowledged.
    pub(super) fn due(&self) -> Option<Instant> {
        (self.last > self.acked).then(|| self.since + self.wait)
    }

    /// Go back to the acknowledgement: what was sent past it goes again,
    /// which a deferred `Behind` asked for too.
    fn rewind(&mut self) {
        self.sent.clear();
        self.bytes = 0;
        self.since = Instant::now();
        self.deferred = None;
    }

    /// A round: rewind, through the next replica, and wait longer before
    /// the next.
    pub(super) fn round(&mut self) {
        self.rewind();
        self.wait = (self.wait * 2).min(self.round * MAX_ROUNDS);
        self.turn += 1;
    }

    /// A receiver's `Behind`: rewind, while the outbox holds more than was
    /// acknowledged, at once or, within [`BEHIND_EVERY`] of the last,
    /// deferred until then. Whether it did now. Nothing in the frame moves
    /// the window: a stale one only sends again what the receiver drops at
    /// its mark.
    pub(super) fn behind(&mut self, now: Instant) -> bool {
        if self.last <= self.acked {
            self.deferred = None;
            return false;
        }
        if self
            .behind
            .is_some_and(|at| now.saturating_duration_since(at) < BEHIND_EVERY)
        {
            self.deferred = Some(self.through());
            return false;
        }
        self.behind = Some(now);
        self.rewind();
        true
    }

    /// When a deferred `Behind` rewinds it.
    pub(super) fn deferred(&self) -> Option<Instant> {
        self.deferred.and(self.behind).map(|at| at + BEHIND_EVERY)
    }

    /// When it goes again next: at its round, or at a deferred `Behind`.
    pub(super) fn next(&self) -> Option<Instant> {
        [self.due(), self.deferred()].into_iter().flatten().min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUND: Duration = Duration::from_secs(1);

    /// A window with `sent` sent past an acknowledgement of 2, the outbox
    /// holding through 5.
    fn window(sent: &[u64]) -> Window {
        let mut window = Window::new(2, 0, ROUND);
        window.holds(5);
        for sequence in sent {
            window.push(*sequence, 10);
        }
        window
    }

    /// A receiver's `Behind` sends the window again from its
    /// acknowledgement at once, through the same replica and with the same
    /// wait; one within `BEHIND_EVERY` of it, once that has passed.
    #[test]
    fn behind_rewinds_at_most_once_every_interval() {
        let mut window = window(&[3, 4, 5]);
        let now = Instant::now();
        assert!(window.behind(now));
        assert_eq!(window.through(), 2, "back to the acknowledgement");
        assert_eq!((window.bytes, window.turn, window.wait), (0, 0, ROUND));
        window.push(3, 10);
        assert!(!window.behind(now + BEHIND_EVERY / 2));
        assert_eq!(window.through(), 3, "a second one too soon waits");
        assert_eq!(window.deferred(), Some(now + BEHIND_EVERY));
        assert_eq!(window.next(), Some(now + BEHIND_EVERY), "before its round");
        assert!(window.behind(now + BEHIND_EVERY));
        assert_eq!(window.through(), 2);
        assert_eq!(window.deferred(), None);
    }

    /// A deferred `Behind` is dropped once the acknowledgement covers all
    /// that was sent: the receiver holds it.
    #[test]
    fn a_full_acknowledgement_cancels_a_deferred_behind() {
        let mut window = window(&[3, 4, 5]);
        let now = Instant::now();
        assert!(window.behind(now));
        window.push(3, 10);
        assert!(!window.behind(now));
        assert!(window.deferred().is_some());
        window.ack(3);
        assert_eq!(window.deferred(), None);
        assert_eq!(window.next(), window.due(), "only its round");
    }

    /// An acknowledgement short of what was sent keeps a deferred `Behind`:
    /// what was sent past it may be what the receiver dropped, and the
    /// round may be far off.
    #[test]
    fn a_partial_acknowledgement_keeps_a_deferred_behind() {
        let mut window = window(&[3, 4, 5]);
        let now = Instant::now();
        assert!(window.behind(now));
        for sequence in [3, 4, 5] {
            window.push(sequence, 10);
        }
        assert!(!window.behind(now + BEHIND_EVERY / 2));
        window.ack(3);
        assert_eq!(window.deferred(), Some(now + BEHIND_EVERY));
        assert_eq!(window.next(), Some(now + BEHIND_EVERY), "before its round");
        assert!(window.behind(now + BEHIND_EVERY));
        assert_eq!(window.through(), 3, "back to the acknowledgement");
    }

    /// An acknowledgement through what was sent when a `Behind` came drops
    /// it, though more was sent since: the receiver holds all the `Behind`
    /// could ask for, and what followed stays sent, the window going on
    /// from it.
    #[test]
    fn an_acknowledgement_through_a_deferred_behind_drops_it_as_sends_go_on() {
        let mut window = window(&[3, 4, 5]);
        window.holds(8);
        let now = Instant::now();
        assert!(window.behind(now));
        for sequence in [3, 4] {
            window.push(sequence, 10);
        }
        assert!(!window.behind(now + BEHIND_EVERY / 2));
        window.push(5, 10);
        window.ack(3);
        assert!(window.deferred().is_some(), "short of what was sent then");
        window.ack(4);
        assert_eq!(window.deferred(), None);
        assert_eq!(window.next(), window.due(), "only its round");
        assert_eq!(window.through(), 5, "what followed stays sent");
        assert!(!window.full(10));
        window.push(6, 10);
        assert_eq!(window.through(), 6);
    }

    /// A `Behind` with nothing past the acknowledgement does nothing, now
    /// or later: a stale one.
    #[test]
    fn behind_with_everything_acknowledged_does_nothing() {
        let mut window = window(&[3, 4, 5]);
        let now = Instant::now();
        assert!(window.behind(now));
        assert!(!window.behind(now));
        window.ack(5);
        assert!(!window.behind(now + BEHIND_EVERY));
        assert_eq!((window.behind, window.deferred()), (Some(now), None));
    }

    /// A round rewinds through the next replica and doubles its wait.
    #[test]
    fn a_round_rewinds_through_the_next_replica() {
        let mut window = window(&[3, 4]);
        window.round();
        assert_eq!(window.through(), 2);
        assert_eq!((window.turn, window.wait), (1, ROUND * 2));
    }
}
