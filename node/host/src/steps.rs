//! The node's clock stepping forward. An idle leader sleeps on a timer
//! until the time, by the node's clock, of the first thing it has due; a
//! step does not move a timer, so each step past [`STEP_MS`] wakes every
//! idle leader to look again, [`SLICE`] at a time ([`look_again`]).

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::node::Inner;

/// How often the node reads its clock against the monotonic one.
const EVERY: Duration = Duration::from_secs(1);

/// How far, in milliseconds, the clock may gain on the monotonic one before
/// the idle leaders look again: well above a time daemon's slew, and with
/// [`EVERY`] a look comes at most two seconds late, and its slice's turn.
const STEP_MS: i128 = 1_000;

/// The most idle leaders [`look_again`] wakes at once, [`PAUSE`] apart: an
/// idle look takes about 150–275 µs of the node's thread (`light-node.md`
/// §3.3, the scale gate's profile), so a slice is at most about 70 ms of
/// it, and the Raft drivers that share the thread run between slices
/// however many leaders the node holds.
pub(crate) const SLICE: usize = 256;

/// The pause between two slices of [`look_again`].
pub(crate) const PAUSE: Duration = Duration::from_millis(50);

/// Wake the listeners of `looks` listening now, [`SLICE`] at a time,
/// [`PAUSE`] apart, oldest first: a leader woken listens again at the
/// back, and is not counted again. At 3,300 idle leaders all have looked
/// within about 1.5 s, at 33,000 within about 15 s.
pub(crate) async fn look_again(looks: &event_listener::Event) {
    let mut left = looks.total_listeners();
    while left > 0 {
        let slice = left.min(SLICE);
        looks.notify_additional(slice);
        left -= slice;
        if left > 0 {
            smol::Timer::after(PAUSE).await;
        }
    }
}

/// Read the node's clock every [`EVERY`] on its runtime: each time it has
/// gained more than [`STEP_MS`] on the monotonic clock over its least lead
/// since the leaders last woke, every listener of `inner.looks` wakes
/// ([`look_again`]), the next read after the wake has run. A
/// slow gain, or the host's sleep, which the monotonic clock does not
/// count, wakes them as a step does. A step back wakes no one: a leader's
/// timer then fires before its time by the clock, and the leader, finding
/// nothing due, sleeps again. A clock that runs slower than the monotonic
/// one (a test's, held still) hides a step up to what it lags by.
pub(crate) async fn watch(inner: Arc<Inner>) {
    let start = Instant::now();
    let lead = || i128::from((inner.clock)()) - start.elapsed().as_millis() as i128;
    let mut floor = lead();
    loop {
        smol::Timer::after(EVERY).await;
        let now = lead();
        if now - floor > STEP_MS {
            look_again(&inner.looks).await;
            floor = lead();
        } else {
            floor = floor.min(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Listeners woken [`SLICE`] at a time, oldest first, until all those
    /// listening at the call have been, one woken listening again not
    /// counted twice.
    #[test]
    fn a_wake_comes_in_slices() {
        let looks = event_listener::Event::new();
        let listeners: Vec<_> = (0..SLICE * 2 + 10).map(|_| looks.listen()).collect();
        // Those woken, dropped once counted.
        let woken = |listeners: &mut Vec<event_listener::EventListener>| {
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            let before = listeners.len();
            listeners
                .retain_mut(|listener| std::pin::Pin::new(listener).poll(&mut cx).is_pending());
            before - listeners.len()
        };
        let mut listeners = listeners;
        smol::block_on(async {
            let wake = look_again(&looks);
            smol::pin!(wake);
            let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
            assert!(wake.as_mut().poll(&mut cx).is_pending());
            assert_eq!(woken(&mut listeners), SLICE, "the first slice alone");
            // One woken listens again, behind the others.
            let again = looks.listen();
            wake.await;
            assert_eq!(woken(&mut listeners), SLICE + 10);
            let mut again = vec![again];
            assert_eq!(woken(&mut again), 0, "not counted twice");
        });
    }
}
