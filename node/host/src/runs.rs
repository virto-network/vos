//! The runs of the credentialed calls a replica forwards, as it applies
//! them: a call forwarded again, whose earlier send ran, is refused
//! `Replayed` at apply, and its client is answered the run of its own
//! send instead. A run is the forward's when its entry names this replica
//! and the forward's token as the input's origin; a copy another replica
//! took is no run of it. A replica that reaches the run by a snapshot
//! applies no entry of it, sees no run, and answers the resend `Replayed`.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Mutex;

use vos_wire::peer::NodeNumber;
use vos_wire::result::{InputRef, Outcome, Run, Step, WorkResult};

use crate::lock;
use crate::store::Origin;

/// The forwards watched, by binding and token, each by how many waits and
/// the last run of it applied.
#[derive(Default)]
pub(crate) struct Runs {
    watched: Mutex<HashMap<([u8; 32], u64), Watched>>,
}

#[derive(Default)]
struct Watched {
    watchers: usize,
    ran: Option<(Outcome, u64)>,
}

impl Runs {
    /// Watch the runs of the credentialed call of `binding` sent under
    /// `token` until the watch is dropped.
    pub(crate) fn watch(&self, binding: [u8; 32], token: u64) -> Watch<'_> {
        let key = (binding, token);
        lock(&self.watched).entry(key).or_default().watchers += 1;
        Watch { runs: self, key }
    }

    /// Keep each watched run in `result`, applied at `index`, whose input
    /// `origins` name `me` as proposing it: before its writes commit, so a
    /// watcher that finds the binding recorded finds the run that recorded
    /// it. A later run replaces an earlier: a run failed before the binding
    /// was recorded leaves the call to come again.
    pub(crate) fn applied(
        &self,
        result: &WorkResult,
        index: u64,
        origins: &[Origin],
        me: NodeNumber,
    ) {
        let mut watched = lock(&self.watched);
        if watched.is_empty() || origins.iter().all(|origin| origin.node != me) {
            return;
        }
        // An input's step, by its position: a workflow's due step is no
        // input's.
        let steps: Vec<&Step> = result
            .steps
            .iter()
            .filter(|step| {
                !matches!(
                    step,
                    Step::Ran(Run {
                        input: InputRef::Due { .. },
                        ..
                    })
                )
            })
            .collect();
        for origin in origins.iter().filter(|origin| origin.node == me) {
            if let Some(Step::Ran(Run {
                input: InputRef::Credentialed { binding },
                outcome,
                ..
            })) = steps.get(usize::from(origin.input))
                && let Some(watched) = watched.get_mut(&(*binding, origin.token))
            {
                watched.ran = Some((outcome.clone(), index));
            }
        }
    }
}

/// One forward's watch of its call's runs.
pub(crate) struct Watch<'a> {
    runs: &'a Runs,
    key: ([u8; 32], u64),
}

impl Watch<'_> {
    /// The last run of the forward's own send this replica applied while
    /// watching, and its index.
    pub(crate) fn ran(&self) -> Option<(Outcome, u64)> {
        lock(&self.runs.watched)
            .get(&self.key)
            .and_then(|watched| watched.ran.clone())
    }
}

impl Drop for Watch<'_> {
    fn drop(&mut self) {
        if let Entry::Occupied(mut watched) = lock(&self.runs.watched).entry(self.key) {
            watched.get_mut().watchers -= 1;
            if watched.get().watchers == 0 {
                watched.remove();
            }
        }
    }
}
