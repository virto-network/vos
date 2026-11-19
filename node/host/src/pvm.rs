//! The node's side of running the agent program ([`vos_exec`]): an
//! agent's applied state, read from a store snapshot, and its programs,
//! from the node's blob store. A store read that fails panics, which the
//! executor turns into an infrastructure fault.

use std::sync::{Arc, Mutex, PoisonError};

use vos_abi::ids::AgentId;
use vos_exec::{ProgramStore, StateReader, value_window};

use crate::blobs::Blobs;
use crate::store::Snapshot;

pub(crate) use vos_exec::{Machines, decode};

/// One agent's applied state, as the agent program reads it.
pub(crate) struct AgentState {
    snapshot: Arc<Snapshot>,
    agent: AgentId,
    /// The row a scan pulled last, read with its key: the scan's read of
    /// its value takes it rather than reading the store again.
    scanned: Mutex<Option<(Vec<u8>, Vec<u8>)>>,
}

impl AgentState {
    /// `agent`'s state at `snapshot`.
    pub(crate) fn of(snapshot: Arc<Snapshot>, agent: AgentId) -> Self {
        Self {
            snapshot,
            agent,
            scanned: Mutex::new(None),
        }
    }

    fn scanned(&self) -> std::sync::MutexGuard<'_, Option<(Vec<u8>, Vec<u8>)>> {
        self.scanned.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// `agent`'s state at `snapshot`, for a refine.
    pub(crate) fn shared(snapshot: Arc<Snapshot>, agent: AgentId) -> Arc<dyn StateReader> {
        Arc::new(Self::of(snapshot, agent))
    }
}

impl StateReader for AgentState {
    fn read(&self, key: &[u8], offset: usize, max: usize) -> Option<(usize, Vec<u8>)> {
        if let Some((_, value)) = self
            .scanned()
            .take_if(|(scanned, _)| scanned.as_slice() == key)
        {
            return Some(value_window(&value, offset, max));
        }
        let value = self.snapshot.get(self.agent, key).expect("a store read")?;
        Some(value_window(&value, offset, max))
    }

    /// The store's scan reads each row's value with its key: the last row
    /// pulled is kept for the scan's read of it, the snapshot's value of
    /// that key whenever it is read.
    fn rows<'a>(
        &'a self,
        prefix: &'a [u8],
        after: Option<&'a [u8]>,
    ) -> Box<dyn Iterator<Item = (Vec<u8>, usize)> + 'a> {
        Box::new(
            self.snapshot
                .scan(self.agent, prefix, after)
                .map(|row| row.expect("a store read"))
                .map(|(key, value)| {
                    let len = value.len();
                    *self.scanned() = Some((key.clone(), value));
                    (key, len)
                }),
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
