//! The node's clock stepping forward. An idle leader sleeps on a timer
//! until the time, by the node's clock, of the first thing it has due; a
//! step does not move a timer, so each step wakes every idle leader to look
//! again.

use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::node::Inner;

/// How often the node reads its clock against the monotonic one.
const EVERY: Duration = Duration::from_secs(1);

/// How far, in milliseconds, the clock may gain on the monotonic one before
/// the idle leaders look again: well above a time daemon's slew, and with
/// [`EVERY`] a look comes at most two seconds late.
const STEP_MS: i128 = 1_000;

/// Read the node's clock every [`EVERY`] on its runtime: each time it has
/// gained more than [`STEP_MS`] on the monotonic clock over its least lead
/// since the leaders last woke, every listener of `inner.looks` wakes. A
/// slow gain, a time daemon's slew adding up, wakes them as a step does. A
/// step back wakes no one: a leader's timer then fires before its time by
/// the clock, and the leader, finding nothing due, sleeps again.
pub(crate) async fn watch(inner: Arc<Inner>) {
    let start = Instant::now();
    let lead = |inner: &Inner| i128::from((inner.clock)()) - start.elapsed().as_millis() as i128;
    let mut floor = lead(&inner);
    loop {
        smol::Timer::after(EVERY).await;
        let now = lead(&inner);
        if now - floor > STEP_MS {
            inner.looks.notify(usize::MAX);
            floor = now;
        } else {
            floor = floor.min(now);
        }
    }
}
