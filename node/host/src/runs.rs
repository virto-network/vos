//! The runs of the credentialed calls a replica forwards, as it applies
//! them: a call forwarded again, whose earlier send ran, is refused
//! `Replayed` at apply, and its client is answered the run it watched
//! apply here instead.

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Mutex;

use vos_wire::result::{InputRef, Outcome, Run, Step, WorkResult};

use crate::lock;

/// The bindings watched, each by how many forwards and the last run
/// applied of it.
#[derive(Default)]
pub(crate) struct Runs {
    watched: Mutex<HashMap<[u8; 32], Watched>>,
}

#[derive(Default)]
struct Watched {
    watchers: usize,
    ran: Option<(Outcome, u64)>,
}

impl Runs {
    /// Watch the runs of the credentialed call of `binding` until the
    /// watch is dropped.
    pub(crate) fn watch(&self, binding: [u8; 32]) -> Watch<'_> {
        lock(&self.watched).entry(binding).or_default().watchers += 1;
        Watch {
            runs: self,
            binding,
        }
    }

    /// Keep each watched call's run in `result`, applied at `index`: before
    /// its writes commit, so a watcher that finds the binding recorded
    /// finds the run that recorded it. A later run replaces an earlier: a
    /// run failed before the binding was recorded leaves the call to come
    /// again.
    pub(crate) fn applied(&self, result: &WorkResult, index: u64) {
        let mut watched = lock(&self.watched);
        if watched.is_empty() {
            return;
        }
        for step in &result.steps {
            if let Step::Ran(Run {
                input: InputRef::Credentialed { binding },
                outcome,
                ..
            }) = step
                && let Some(watched) = watched.get_mut(binding)
            {
                watched.ran = Some((outcome.clone(), index));
            }
        }
    }
}

/// One forward's watch of its call's runs.
pub(crate) struct Watch<'a> {
    runs: &'a Runs,
    binding: [u8; 32],
}

impl Watch<'_> {
    /// The last run of the call this replica applied while watching, and
    /// its index.
    pub(crate) fn ran(&self) -> Option<(Outcome, u64)> {
        lock(&self.runs.watched)
            .get(&self.binding)
            .and_then(|watched| watched.ran.clone())
    }
}

impl Drop for Watch<'_> {
    fn drop(&mut self) {
        if let Entry::Occupied(mut watched) = lock(&self.runs.watched).entry(self.binding) {
            watched.get_mut().watchers -= 1;
            if watched.get().watchers == 0 {
                watched.remove();
            }
        }
    }
}
