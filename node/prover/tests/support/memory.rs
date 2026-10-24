//! A job table in memory, kept across no restart of the test's process.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use vos_venue::vos_statement::StatementId;
use vos_wire::ids::AgentId;

use vos_node_prover::{Job, Jobs};

/// Jobs and watermarks in memory, shared by its clones: a clone outlives a
/// worker dropped as a stopped node's, for the next to open.
#[derive(Clone, Default)]
pub(crate) struct MemoryJobs {
    held: Arc<Mutex<Held>>,
}

#[derive(Default)]
struct Held {
    jobs: BTreeMap<(AgentId, [u8; 32]), Job>,
    watermarks: BTreeMap<AgentId, u64>,
}

impl MemoryJobs {
    fn held(&self) -> std::sync::MutexGuard<'_, Held> {
        self.held
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl Jobs for MemoryJobs {
    fn get(&self, agent: AgentId, id: &StatementId) -> Result<Option<Job>, String> {
        Ok(self.held().jobs.get(&(agent, id.0)).cloned())
    }

    fn put(&self, id: &StatementId, job: &Job) -> Result<(), String> {
        self.held().jobs.insert((job.agent, id.0), job.clone());
        Ok(())
    }

    fn remove(&self, agent: AgentId, id: &StatementId) -> Result<(), String> {
        self.held().jobs.remove(&(agent, id.0));
        Ok(())
    }

    fn all(&self) -> Result<Vec<(StatementId, Job)>, String> {
        Ok(self
            .held()
            .jobs
            .iter()
            .map(|((_, id), job)| (StatementId(*id), job.clone()))
            .collect())
    }

    fn watermark(&self, agent: AgentId) -> Result<u64, String> {
        Ok(self.held().watermarks.get(&agent).copied().unwrap_or(0))
    }

    fn set_watermark(&self, agent: AgentId, index: u64) -> Result<(), String> {
        self.held().watermarks.insert(agent, index);
        Ok(())
    }
}
