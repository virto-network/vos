//! The leader's sweep of its agent's due index: expired sessions, and
//! workflows' steps.

use std::ops::Bound;
use std::time::{Duration, Instant};

use vos_wire::ids::AgentId;
use vos_wire::keys::Due;
use vos_wire::result::Write;
use vos_wire::{defaults, keys};

use super::Leader;
use crate::fault::{Fault, read};
use crate::store::Snapshot;

/// How often an idle leader looks again at its first due row: a clock
/// stepped forward does not move a timer.
const SWEEP_RECHECK: Duration = Duration::from_secs(5);
/// How long a leader adds no sweep once one left its first due row in
/// place.
const SWEEP_PAUSE: Duration = Duration::from_secs(60);

/// The leader's last sweeps, which pace its next, and where its scans of
/// the due index start.
#[derive(Default)]
pub(super) struct Sweeps {
    /// The first row of the due index when the last sweep applied, or
    /// failed alone, and when.
    swept: Option<((u64, Due), Instant)>,
    /// That a sweep left its first due row in place, said once.
    stuck: bool,
    /// A key at or below every row the due index holds: the first row the
    /// last scan found, or past every row when it found none, lowered by
    /// each row this leadership's batches write since. A sweep deletes
    /// rows from the index's start, and its scans would otherwise pass
    /// over each deletion until the store compacts it away. None until a
    /// scan from the start.
    floor: Option<Vec<u8>>,
}

impl Sweeps {
    /// A sweep that found `first` the first row of the due index applied,
    /// or failed alone: the next waits while it left that row in place.
    pub(super) fn swept(&mut self, first: (u64, Due)) {
        self.swept = Some((first, Instant::now()));
    }

    /// A batch of this leadership's, about to fly, writes `writes`: a row
    /// of the due index it writes may sit below the floor.
    pub(super) fn writes(&mut self, writes: &[Write]) {
        let Some(floor) = self.floor.as_mut() else {
            return;
        };
        let prefix = keys::due_prefix();
        for write in writes {
            if write.value.is_some() && write.key.starts_with(&prefix) && write.key < *floor {
                floor.clone_from(&write.key);
            }
        }
    }

    /// A batch in flight did not apply as proposed: the rows its writes
    /// deleted may stand, below the floor its scan left. The next scan
    /// starts from the index's start.
    pub(super) fn lost_writes(&mut self) {
        self.floor = None;
    }

    /// The first row of `agent`'s due index on `snapshot`, the state with
    /// every batch of this leadership's that flies over it: the floor rises
    /// to it.
    pub(super) fn first_due(
        &mut self,
        snapshot: &Snapshot,
        agent: AgentId,
    ) -> Result<Option<(u64, Due)>, Fault> {
        let prefix = keys::due_prefix();
        let start = self
            .floor
            .as_deref()
            .map_or(Bound::Unbounded, Bound::Included);
        let mut found = None;
        for row in snapshot.scan_from(agent, &prefix, start) {
            let (key, _) = row?;
            if let Some(due) = keys::due_entry(&key) {
                found = Some((key, due));
                break;
            }
        }
        let (key, due) = found.unzip();
        self.floor = Some(key.unwrap_or_else(past_every_row));
        Ok(due)
    }

    /// The rows of `agent`'s due index due at `time`, earliest first, as
    /// many as a sweep lists.
    pub(super) fn due_rows(
        &self,
        snapshot: &Snapshot,
        agent: AgentId,
        time: u64,
    ) -> Result<Vec<(u64, Due)>, Fault> {
        let prefix = keys::due_prefix();
        let start = self
            .floor
            .as_deref()
            .map_or(Bound::Unbounded, Bound::Included);
        let keys = snapshot
            .scan_from(agent, &prefix, start)
            .map(|row| row.map(|(key, _)| key));
        Ok(keys::due_rows(keys, time, defaults::SWEEP_LIMIT)?)
    }
}

/// A key past every row of the due index: the last binding's at the last
/// time.
fn past_every_row() -> Vec<u8> {
    keys::due(u64::MAX, Due::Binding([0xff; 32]))
}

impl Leader {
    /// How long until an idle leader sweeps, or looks again: zero when a
    /// sweep is due now, none when the agent holds no session.
    pub(super) fn sweep_wait(&mut self) -> Option<Duration> {
        let snapshot = self.inner.store.snapshot();
        let first = match self.sweeps.first_due(&snapshot, self.id) {
            Ok(Some(first)) => first,
            Ok(None) => return None,
            Err(_) => return Some(SWEEP_RECHECK),
        };
        let floor = read::<u64>(&snapshot, self.id, &keys::batch_time())
            .ok()
            .flatten()
            .unwrap_or(0);
        let now = (self.inner.clock)().max(floor);
        if self.sweeps(first, now) {
            return Some(Duration::ZERO);
        }
        let wait = match self.sweeps.swept {
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
        let sweeps = &mut self.sweeps;
        match sweeps.swept {
            Some((left, at)) if left == first && at.elapsed() < SWEEP_PAUSE => {
                if !sweeps.stuck {
                    sweeps.stuck = true;
                    tracing::warn!(
                        agent = self.id.0,
                        "a sweep left its first due row in place; sweeps pause"
                    );
                }
                false
            }
            _ => {
                sweeps.stuck = false;
                true
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use vos_wire::ids::{AgentId, SessionId};
    use vos_wire::result::Write;

    use super::*;
    use crate::store::{Fjall, PersistMode};

    const AGENT: AgentId = AgentId(1);

    fn due(at: u64) -> Vec<u8> {
        keys::due(at, Due::Session(SessionId(at)))
    }

    fn put(key: Vec<u8>) -> Write {
        Write {
            key,
            value: Some(Vec::new()),
        }
    }

    fn apply(store: &Fjall, index: u64, writes: &[Write]) {
        let mut batch = store.batch();
        batch.apply(AGENT, 0, index, writes);
        batch.commit(PersistMode::Buffer).unwrap();
    }

    /// A scan starts at the first row the last one found, and a row this
    /// leadership writes below it lowers it: no row is passed over.
    #[test]
    fn the_due_floor_rises_with_scans_and_falls_with_writes() {
        let dir = tempfile::tempdir().unwrap();
        let store = Fjall::open(dir.path()).unwrap();
        let mut sweeps = Sweeps::default();
        apply(&store, 1, &[put(due(10)), put(due(20)), put(due(30))]);
        let first = |sweeps: &mut Sweeps| {
            sweeps
                .first_due(&store.snapshot(), AGENT)
                .unwrap()
                .map(|(at, _)| at)
        };
        assert_eq!(first(&mut sweeps), Some(10));
        // Swept: the first two rows go.
        let gone: Vec<Write> = [10, 20]
            .map(|at| Write {
                key: due(at),
                value: None,
            })
            .to_vec();
        apply(&store, 2, &gone);
        assert_eq!(first(&mut sweeps), Some(30));
        assert_eq!(sweeps.floor.as_deref(), Some(&due(30)[..]));
        // A batch of this leadership's writes a row due sooner.
        let sooner = [put(due(15))];
        sweeps.writes(&sooner);
        apply(&store, 3, &sooner);
        assert_eq!(first(&mut sweeps), Some(15));
        let rows = sweeps.due_rows(&store.snapshot(), AGENT, 40).unwrap();
        assert_eq!(rows.iter().map(|(at, _)| *at).collect::<Vec<_>>(), [15, 30]);
        // None left: the floor passes every row, and a later write lowers
        // it again.
        apply(
            &store,
            4,
            &[15, 30].map(|at| Write {
                key: due(at),
                value: None,
            }),
        );
        assert_eq!(first(&mut sweeps), None);
        let later = [put(due(50))];
        sweeps.writes(&later);
        apply(&store, 5, &later);
        assert_eq!(first(&mut sweeps), Some(50));
    }
}
