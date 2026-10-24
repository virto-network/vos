//! Statements this node's prover proved, recorded in their agent: the
//! leader proposes `Input::Proven` for each the worker handed over that
//! the agent does not hold recorded, from its replica's state, never
//! queued. Refine keeps the first proof of an id alone.

use vos_wire::batch::Input;
use vos_wire::keys;

use super::Leader;
use crate::fault::Fault;
use crate::node::Pending;
use crate::store::Snapshot;

/// The most statements one batch records.
const PROVEN: usize = 16;

impl Leader {
    /// Whether a statement proved here waits to be recorded.
    pub(super) fn proofs_due(&self) -> bool {
        self.proofs(&self.inner.store.snapshot())
            .is_ok_and(|proofs| !proofs.is_empty())
    }

    /// The statements proved here that `snapshot`'s agent does not hold
    /// recorded, at most [`PROVEN`]; those it holds are forgotten.
    pub(super) fn proofs(&self, snapshot: &Snapshot) -> Result<Vec<Pending>, Fault> {
        let mut due = Vec::new();
        for (id, window, proof) in self.inner.unrecorded.of(self.id) {
            if snapshot
                .get(self.id, &keys::proven(window, &id.0))?
                .is_some()
            {
                self.inner.unrecorded.recorded(self.id, &id);
                continue;
            }
            if due.len() < PROVEN {
                due.push(Pending::Duty(Input::Proven {
                    window,
                    id: id.0,
                    proof,
                }));
            }
        }
        Ok(due)
    }
}
