//! The leader's `Cut` marker: an empty work result an idle agent of a
//! space is given once the leader's own clock passes the boundary after
//! the agent's batch-time mark, when a read waits on the mark's window or
//! the agent reports every window, so its apply records the window's cut
//! though no input came. The marker is timed at the leader's clock, never
//! at the boundary: a leader whose clock trails cuts late, never wrongly.

use std::sync::Arc;
use std::time::Duration;

use vos_wire::apply::Waits;
use vos_wire::batch::Batch;
use vos_wire::ids::AgentId;
use vos_wire::keys;
use vos_wire::result::WorkResult;
use vos_wire::{SpaceId, WindowClock};

use super::{Ended, Leader};
use crate::fault::{Fault, read};
use crate::random;
use crate::store::Snapshot;

/// How often an idle leader looks again at the next boundary: a clock
/// stepped forward does not move a timer.
const CUT_RECHECK: Duration = Duration::from_secs(2);

/// The clock of `snapshot`'s agent's space, if it belongs to one.
fn space_clock(snapshot: &Snapshot, agent: AgentId) -> Result<Option<WindowClock>, Fault> {
    let space = read::<SpaceId>(snapshot, agent, &keys::space())?;
    if space.is_none_or(|space| space == SpaceId::NONE) {
        return Ok(None);
    }
    read::<WindowClock>(snapshot, agent, &keys::clock())
}

/// The first boundary past the agent's batch-time mark on its space's
/// clock, when its apply would cut there: a read waits on the mark's
/// window ([`keys::reading`]), or the agent reports every window; none
/// otherwise, and when it belongs to no space.
fn cut_due(snapshot: &Snapshot, agent: AgentId) -> Result<Option<u64>, Fault> {
    let Some(clock) = space_clock(snapshot, agent)? else {
        return Ok(None);
    };
    let mark = read::<u64>(snapshot, agent, &keys::batch_time())?.unwrap_or(0);
    let waits = Waits {
        every: snapshot.get(agent, &keys::every_window())?.is_some(),
        reading: read::<u64>(snapshot, agent, &keys::reading())?,
    };
    let boundary = clock.boundary(clock.window(mark).unwrap_or(0));
    Ok(boundary.filter(|boundary| waits.cuts(&clock, mark, *boundary).is_some()))
}

/// What a marker is made of, as `snapshot` holds the agent: the first
/// boundary past its batch-time mark at which it cuts, its version, its
/// batch-time floor and its applied index.
fn marker_state(
    snapshot: &Snapshot,
    agent: AgentId,
) -> Result<(Option<u64>, u64, u64, u64), Fault> {
    let due = cut_due(snapshot, agent)?;
    let version = read::<u64>(snapshot, agent, &keys::version())?.unwrap_or(0);
    let floor = read::<u64>(snapshot, agent, &keys::batch_time())?.unwrap_or(0);
    let applied = snapshot.applied(agent)?.unwrap_or(0);
    Ok((due, version, floor, applied))
}

impl Leader {
    /// How long until an idle leader appends a marker: zero when one is
    /// due now, its clock at or past the first boundary after the agent's
    /// batch-time mark; none when the agent cuts there no window.
    pub(super) fn cut_wait(&self) -> Option<Duration> {
        let snapshot = self.inner.store.snapshot();
        let boundary = match cut_due(&snapshot, self.id) {
            Ok(Some(boundary)) => boundary,
            Ok(None) => return None,
            Err(_) => return Some(CUT_RECHECK),
        };
        let now = (self.inner.clock)();
        let wait = Duration::from_millis(boundary.saturating_sub(now));
        Some(if wait.is_zero() {
            wait
        } else {
            wait.clamp(Duration::from_millis(1), CUT_RECHECK)
        })
    }

    /// Append a marker, if one is still due on the applied state: an empty
    /// work result at the agent's version, timed at this node's clock, not
    /// refined. False when a hook stops the leader.
    pub(super) async fn marker(&mut self) -> bool {
        let snapshot = Arc::new(self.inner.store.snapshot());
        let (boundary, version, floor) = match marker_state(&snapshot, self.id) {
            Ok((boundary, version, floor, applied)) => {
                self.applied = applied;
                (boundary, version, floor)
            }
            Err(fault) => {
                self.retry(Vec::new(), fault).await;
                return true;
            }
        };
        let time = self.time(floor);
        let due = boundary.is_some_and(|boundary| boundary <= time);
        if !due {
            return true;
        }
        let seed = random();
        let batch = Batch {
            version,
            time,
            seed,
            budget: 0,
            inputs: Vec::new(),
        };
        let result = WorkResult {
            version,
            time,
            seed,
            steps: Vec::new(),
        };
        match self
            .execute(snapshot, batch, Vec::new(), Some(result))
            .await
        {
            Ok(Ended::Done(_)) => {
                self.backoff.reset();
                self.inner.hooks.after_commit(self.id, self.applied)
            }
            Ok(Ended::Lost) => true,
            // Applied as no writes: tried again after a backoff.
            Ok(Ended::Skipped) => {
                let skipped = Fault::Infrastructure("a marker applied as no writes".into());
                self.retry(Vec::new(), skipped).await;
                true
            }
            Err(fault) if self.ended_by(&fault) => false,
            Err(fault) => {
                self.retry(Vec::new(), fault).await;
                true
            }
        }
    }
}
