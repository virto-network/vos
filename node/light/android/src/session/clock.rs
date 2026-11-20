// SPDX-FileCopyrightText: 2026 Virto
// SPDX-License-Identifier: AGPL-3.0-or-later

//! A session's reading of the node's clock.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use vos_light::route::Purpose;
use vos_light::wire;

use super::jittered;
use crate::job::now_ms;
use crate::net::Net;

/// The furthest the node's time may be from the device's: past it, a relay
/// that lies about the time could keep a confirmed proof for later.
pub(super) const CLOCK_SKEW_MS: u64 = 300_000;
/// How long a session uses its reading of the node's clock. A reading
/// is an offset from the device's clock, which drifts a few milliseconds
/// in that time; what makes it wrong is a step of the device's clock,
/// which [`CLOCK_STEP_MS`] catches. The bound is on rendezvous an hour
/// (at most 30 in the foreground): each reading is a fetch, a rendezvous,
/// so a session reads again every 4 to 12 minutes ([`CLOCK_EVERY`]), about
/// seven an hour.
pub(super) const CLOCK_LIFE: Duration = Duration::from_secs(15 * 60);
/// How often a session reads the node's clock again, about: each reading
/// draws its renewal between half and one and a half of it.
pub(super) const CLOCK_EVERY: Duration = Duration::from_secs(8 * 60);
/// The most the device's clock may move apart from its monotonic clock
/// while a reading is used: past it the clock was set, or the device
/// slept, and the node's clock is read again.
pub(super) const CLOCK_STEP_MS: u64 = 2_000;
/// The spread of a session's first reading after its grant.
pub(super) const CLOCK_SPREAD: Duration = Duration::from_secs(2);
/// How often a session's clock task looks at its reading.
pub(super) const CLOCK_TICK: Duration = Duration::from_secs(5);
/// The node's clock as a session read it: its offset from the device's
/// clock, and when it was read, by the device's clock and its monotonic
/// one.
#[derive(Clone, Copy, Debug)]
pub(super) struct Clock {
    offset_ms: i64,
    wall_ms: u64,
    at: Instant,
    /// When the session reads it again.
    renew: Duration,
}

impl Clock {
    /// The node's time now: its time at the reading, moved on by the
    /// monotonic clock, which a step of the device's clock does not move;
    /// none past [`CLOCK_LIFE`], or once the device's clock moved apart from
    /// the monotonic one (it was set, or the device slept, which the
    /// monotonic clock does not count).
    fn now(&self) -> Option<u64> {
        let elapsed = self.at.elapsed();
        if elapsed >= CLOCK_LIFE {
            return None;
        }
        let elapsed_ms = elapsed.as_millis() as u64;
        let moved = now_ms() as i64 - self.wall_ms as i64;
        if moved.abs_diff(elapsed_ms as i64) > CLOCK_STEP_MS {
            return None;
        }
        self.wall_ms
            .checked_add_signed(self.offset_ms)?
            .checked_add(elapsed_ms)
    }

    fn due(&self) -> bool {
        self.now().is_none() || self.at.elapsed() >= self.renew
    }
}

/// A session's reading of the node's clock, its own: the time a gateway
/// answered reaches every expiry set from it, so a reading is shared only
/// among the calls of the one session that asked them, which its server
/// joins anyway (`light-node.md` §6.2).
#[derive(Default)]
pub(super) struct SessionClock {
    pub(super) reading: Mutex<Option<Clock>>,
    /// Held while the clock is read, so a call waits for a read in flight
    /// rather than making another.
    pub(super) read: tokio::sync::Mutex<()>,
    /// The task reading it again while the session is open.
    pub(super) task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// A read made while a form is read.
    pub(super) meanwhile: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl SessionClock {
    pub(super) fn current(&self) -> Option<u64> {
        self.reading
            .lock()
            .expect("clock poisoned")
            .as_ref()
            .and_then(Clock::now)
    }

    /// The node's time now: this session's reading, or one read now.
    pub(super) async fn now(
        &self,
        net: &Net,
        space: [u8; 32],
        session: u64,
    ) -> Result<u64, String> {
        if let Some(now) = self.current() {
            return Ok(now);
        }
        self.renew(net, space, session).await?;
        self.current()
            .ok_or_else(|| "the device's clock moved while the node's time was read".into())
    }

    /// The clock read again, if its reading is due.
    pub(super) async fn renew(
        &self,
        net: &Net,
        space: [u8; 32],
        session: u64,
    ) -> Result<(), String> {
        let _reading = self.read.lock().await;
        let due = self
            .reading
            .lock()
            .expect("clock poisoned")
            .as_ref()
            .is_none_or(Clock::due);
        if due {
            let clock = read_clock(net, space, session).await?;
            *self.reading.lock().expect("clock poisoned") = Some(clock);
        }
        Ok(())
    }

    pub(super) fn stop(&self) {
        for task in [&self.task, &self.meanwhile] {
            if let Some(task) = task.lock().expect("clock poisoned").take() {
                task.abort();
            }
        }
    }
}

/// The node's clock, read on a fetch of its own (the session's fetch spare
/// if one is built), refused when it is further from the device's than
/// [`CLOCK_SKEW_MS`]. The device's clock is taken as the answer arrives, so
/// the reading errs early by the trip and an expiry set from it never
/// later than the node's time says.
pub(super) async fn read_clock(net: &Net, space: [u8; 32], session: u64) -> Result<Clock, String> {
    let answer = net
        .request_for(space, Purpose::Fetch, &wire::time_request(), Some(session))
        .await?;
    let (wall_ms, at) = (now_ms(), Instant::now());
    let node = wire::time_answer(&answer).map_err(|error| error.to_string())?;
    if node.abs_diff(wall_ms) > CLOCK_SKEW_MS {
        return Err("the node's time is minutes off this device's".into());
    }
    Ok(Clock {
        offset_ms: node as i64 - wall_ms as i64,
        wall_ms,
        at,
        renew: jittered(CLOCK_EVERY),
    })
}
