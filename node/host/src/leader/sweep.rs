//! The leader's sweep of its agent's due index: expired sessions, and
//! workflows' steps.

use std::time::Duration;

use vos_wire::ids::AgentId;
use vos_wire::keys::Due;
use vos_wire::{defaults, keys};

use super::Leader;
use crate::fault::{Fault, read};
use crate::node::Inner;
use crate::store::Snapshot;

/// How often an idle leader looks again at its first due row: a clock
/// stepped forward does not move a timer.
const SWEEP_RECHECK: Duration = Duration::from_secs(5);
/// How long a leader adds no sweep once one left its first due row in
/// place.
const SWEEP_PAUSE: Duration = Duration::from_secs(60);

impl Leader {
    /// How long until an idle leader sweeps, or looks again: zero when a
    /// sweep is due now, none when the agent holds no session.
    pub(super) fn sweep_wait(&mut self, inner: &Inner) -> Option<Duration> {
        let snapshot = inner.store.snapshot();
        let first = match first_due(&snapshot, self.id) {
            Ok(Some(first)) => first,
            Ok(None) => return None,
            Err(_) => return Some(SWEEP_RECHECK),
        };
        let floor = read::<u64>(&snapshot, self.id, &keys::batch_time())
            .ok()
            .flatten()
            .unwrap_or(0);
        let now = (inner.clock)().max(floor);
        if self.sweeps(first, now) {
            return Some(Duration::ZERO);
        }
        let wait = match self.swept {
            // Paused on this row: until the pause ends.
            Some((left, at)) if left == first && first.0 <= now => {
                SWEEP_PAUSE.saturating_sub(at.elapsed())
            }
            _ => Duration::from_millis(first.0.saturating_sub(now)),
        };
        Some(wait.clamp(Duration::from_millis(1), SWEEP_RECHECK))
    }

    /// Whether a batch timed `time` sweeps, the first row of the due index
    /// being `first`: once it is due, unless the last sweep left it in
    /// place a moment ago.
    pub(super) fn sweeps(&mut self, first: (u64, Due), time: u64) -> bool {
        if first.0 > time {
            return false;
        }
        match self.swept {
            Some((left, at)) if left == first && at.elapsed() < SWEEP_PAUSE => {
                if !self.stuck {
                    self.stuck = true;
                    tracing::warn!(
                        agent = self.id.0,
                        "a sweep left its first due row in place; sweeps pause"
                    );
                }
                false
            }
            _ => {
                self.stuck = false;
                true
            }
        }
    }
}

/// The first row of `agent`'s due index: the earliest, its time and entry.
pub(super) fn first_due(snapshot: &Snapshot, agent: AgentId) -> Result<Option<(u64, Due)>, Fault> {
    Ok(due_rows_until(snapshot, agent, u64::MAX, 1)?.pop())
}

/// The rows of `agent`'s due index due at `time`, earliest first, as many
/// as a sweep lists.
pub(super) fn due_rows(
    snapshot: &Snapshot,
    agent: AgentId,
    time: u64,
) -> Result<Vec<(u64, Due)>, Fault> {
    due_rows_until(snapshot, agent, time, defaults::SWEEP_LIMIT)
}

/// At most `limit` rows of `agent`'s due index due at `time`, earliest
/// first; a key under the index that names no entry is passed over.
fn due_rows_until(
    snapshot: &Snapshot,
    agent: AgentId,
    time: u64,
    limit: usize,
) -> Result<Vec<(u64, Due)>, Fault> {
    let mut due = Vec::new();
    for row in snapshot.scan(agent, &keys::due_prefix(), None) {
        let (key, _) = row.map_err(|error| Fault::Infrastructure(error.to_string()))?;
        let Some((at, entry)) = keys::due_entry(&key) else {
            continue;
        };
        if at > time || due.len() == limit {
            break;
        }
        due.push((at, entry));
    }
    Ok(due)
}
