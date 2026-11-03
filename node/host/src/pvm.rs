//! The node's side of running the agent program ([`vos_exec`]): an
//! agent's applied state, read from a store snapshot, and its programs,
//! from the node's blob store. A store read that fails panics, which the
//! executor turns into an infrastructure fault.

use std::sync::Arc;

use vos_exec::{ProgramStore, StateReader};
use vos_wire::ids::AgentId;

use crate::blobs::Blobs;
use crate::store::Snapshot;

pub(crate) use vos_exec::{Machines, decode};

/// One agent's applied state, as the agent program reads it.
pub(crate) struct AgentState {
    snapshot: Arc<Snapshot>,
    agent: AgentId,
}

impl AgentState {
    /// `agent`'s state at `snapshot`.
    pub(crate) fn of(snapshot: Arc<Snapshot>, agent: AgentId) -> Self {
        Self { snapshot, agent }
    }

    /// `agent`'s state at `snapshot`, for a refine.
    pub(crate) fn shared(snapshot: Arc<Snapshot>, agent: AgentId) -> Arc<dyn StateReader> {
        Arc::new(Self::of(snapshot, agent))
    }
}

impl StateReader for AgentState {
    fn read(&self, key: &[u8]) -> Option<Vec<u8>> {
        self.snapshot.get(self.agent, key).expect("a store read")
    }

    fn rows<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> Box<dyn Iterator<Item = (Vec<u8>, Vec<u8>)> + 'a> {
        Box::new(
            self.snapshot
                .scan(self.agent, prefix, after)
                .map(|row| row.expect("a store read")),
        )
    }
}

/// The programs agents install, from the node's blob store.
impl ProgramStore for Blobs {
    fn get(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        Blobs::get(self, hash).expect("a blob read")
    }

    fn pinned_by(&self, hash: &[u8; 32], agent: AgentId) -> bool {
        Blobs::pinned_by(self, hash, agent.0).expect("a pin read")
    }
}
