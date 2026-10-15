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
    pub(super) acked: u64,
    /// The last sequence the outbox holds for the target, as last read.
    pub(super) last: u64,
    /// The sequences sent past `acked`, with their sizes.
    pub(super) sent: VecDeque<(u64, usize)>,
    pub(super) bytes: usize,
    /// When the acknowledgement last moved, or the window last went again.
    since: Instant,
    /// How long after `since` it goes again.
    wait: Duration,
    /// The first wait, to which an acknowledgement brings it back.
    round: Duration,
    /// Which replica of the target it goes through, when it goes through
    /// one: the same for a whole window, another each round.
    pub(super) turn: u64,
    /// When a receiver's `Behind` last sent it again.
    behind: Option<Instant>,
    /// A `Behind` came too soon after that: it sends again once
    /// [`BEHIND_EVERY`] has passed.
    deferred: bool,
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
            deferred: false,
        }
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
        // The receiver moves on: a deferred `Behind` would send again what
        // it may hold, which its round sends if it does not.
        self.deferred = false;
        while let Some((sent, size)) = self.sent.front().copied() {
            if sent > sequence {
                break;
            }
            self.sent.pop_front();
            self.bytes -= size;
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
        self.deferred = false;
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
            self.deferred = false;
            return false;
        }
        if self
            .behind
            .is_some_and(|at| now.saturating_duration_since(at) < BEHIND_EVERY)
        {
            self.deferred = true;
            return false;
        }
        self.behind = Some(now);
        self.rewind();
        true
    }

    /// When a deferred `Behind` rewinds it.
    pub(super) fn deferred(&self) -> Option<Instant> {
        self.behind
            .filter(|_| self.deferred)
            .map(|at| at + BEHIND_EVERY)
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
        window.last = 5;
        for sequence in sent {
            window.sent.push_back((*sequence, 10));
            window.bytes += 10;
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
        window.sent.push_back((3, 10));
        assert!(!window.behind(now + BEHIND_EVERY / 2));
        assert_eq!(window.through(), 3, "a second one too soon waits");
        assert_eq!(window.deferred(), Some(now + BEHIND_EVERY));
        assert_eq!(window.next(), Some(now + BEHIND_EVERY), "before its round");
        assert!(window.behind(now + BEHIND_EVERY));
        assert_eq!(window.through(), 2);
        assert_eq!(window.deferred(), None);
    }

    /// A deferred `Behind` is dropped once the acknowledgement moves: the
    /// receiver took more, and what it may hold would go again.
    #[test]
    fn an_acknowledgement_cancels_a_deferred_behind() {
        let mut window = window(&[3, 4, 5]);
        let now = Instant::now();
        assert!(window.behind(now));
        window.sent.push_back((3, 10));
        window.bytes += 10;
        assert!(!window.behind(now));
        assert!(window.deferred().is_some());
        window.ack(3);
        assert_eq!(window.deferred(), None);
        assert_eq!(window.next(), window.due(), "only its round");
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
