//! The leader's `Cut` marker: an empty work result an idle agent of a
//! space is given once the leader's own clock passes the boundary after
//! the agent's batch-time mark, so its apply records the window's cut
//! though no input came. The marker is timed at the leader's clock, never
//! at the boundary: a leader whose clock trails cuts late, never wrongly.

use std::sync::Arc;
use std::time::Duration;

use vos_wire::batch::Batch;
use vos_wire::ids::RequestId;
use vos_wire::keys;
use vos_wire::records::PendingRead;
use vos_wire::result::{InputRef, Outcome, Run, Step, WorkResult, Write};
use vos_wire::{Encode, SpaceId, WindowClock};

use super::{Ended, Leader};
use crate::fault::{Fault, read};
use crate::random;
use crate::store::Snapshot;

/// How often an idle leader looks again at the next boundary: a clock
/// stepped forward does not move a timer.
const CUT_RECHECK: Duration = Duration::from_secs(2);

/// The clock of `snapshot`'s agent's space, if it belongs to one.
fn space_clock(
    snapshot: &Snapshot,
    agent: vos_wire::ids::AgentId,
) -> Result<Option<WindowClock>, Fault> {
    let space = read::<SpaceId>(snapshot, agent, &keys::space())?;
    if space.is_none_or(|space| space == SpaceId::NONE) {
        return Ok(None);
    }
    read::<WindowClock>(snapshot, agent, &keys::clock())
}

/// The first boundary past `mark` on `clock`.
fn next_boundary(clock: &WindowClock, mark: u64) -> Option<u64> {
    clock.boundary(clock.window(mark).unwrap_or(0))
}

impl Leader {
    /// How long until an idle leader appends a marker: zero when one is
    /// due now, its clock at or past the first boundary after the agent's
    /// batch-time mark; none when the agent belongs to no space.
    pub(super) fn cut_wait(&self) -> Option<Duration> {
        let snapshot = self.inner.store.snapshot();
        let due = (|| {
            let Some(clock) = space_clock(&snapshot, self.id)? else {
                return Ok(None);
            };
            let mark = read::<u64>(&snapshot, self.id, &keys::batch_time())?.unwrap_or(0);
            Ok::<_, Fault>(next_boundary(&clock, mark))
        })();
        let boundary = match due {
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
        let state = (|| {
            let clock = space_clock(&snapshot, self.id)?;
            let version = read::<u64>(&snapshot, self.id, &keys::version())?.unwrap_or(0);
            let floor = read::<u64>(&snapshot, self.id, &keys::batch_time())?.unwrap_or(0);
            self.applied = snapshot.applied(self.id)?.unwrap_or(0);
            Ok::<_, Fault>((clock, version, floor))
        })();
        let (clock, version, floor) = match state {
            Ok(state) => state,
            Err(fault) => {
                self.retry(Vec::new(), fault).await;
                return true;
            }
        };
        let time = self.time(floor);
        let due = clock
            .and_then(|clock| next_boundary(&clock, floor))
            .is_some_and(|boundary| boundary <= time);
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
            Ok(Ended::Lost | Ended::Skipped) => true,
            Err(Fault::Storage(message)) => {
                tracing::error!(
                    agent = self.id.0,
                    "a commit failed ({message}); the node stops and needs a restart"
                );
                self.inner.halt();
                false
            }
            Err(Fault::Invariant(message)) => {
                tracing::error!(agent = self.id.0, "{message}; the agent stops");
                false
            }
            Err(fault) => {
                self.retry(Vec::new(), fault).await;
                true
            }
        }
    }

    /// The step a test's hook adds to a refined batch's result timed
    /// `time`: the pending request it names, in the window of `time`
    /// ([`crate::Hooks::request_at_cut`]). A workflow's due step in form,
    /// so it answers no input.
    pub(super) fn requested(&self, snapshot: &Snapshot, time: u64) -> Result<Option<Step>, Fault> {
        let Some((id, read)) = self.inner.hooks.request_at_cut(self.id, time) else {
            return Ok(None);
        };
        let Some(window) = space_clock(snapshot, self.id)?.and_then(|clock| clock.window(time))
        else {
            return Ok(None);
        };
        Ok(Some(request_step(window, id, &read)))
    }
}

/// A step recording `read` as `id`'s pending request of `window`.
fn request_step(window: u64, id: RequestId, read: &PendingRead) -> Step {
    Step::Ran(Run {
        input: InputRef::Due {
            workflow: id.workflow,
        },
        outcome: Outcome::Done(Vec::new()),
        instances: Vec::new(),
        writes: vec![Write {
            key: keys::request(window, id),
            value: Some(read.encode()),
        }],
        committed: Vec::new(),
        messages: Vec::new(),
        attests: Vec::new(),
        pages: Vec::new(),
        gas_used: 0,
    })
}
