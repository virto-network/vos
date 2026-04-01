//! Service registry — manages the lifecycle of VOS services.

use vos_abi::service::ServiceId;

/// State of a registered service.
#[derive(Debug, Clone, Copy, PartialEq, Eq, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
pub enum ServiceState {
    /// Service has been registered but not yet invoked.
    Created,
    /// Service is running and can receive transfers.
    Running,
    /// Service is suspended mid-execution (yielded).
    Suspended,
    /// Service has stopped (cleanly or due to error).
    Stopped,
}

// --- Persistent ServiceTable (rkyv-serializable) ---

/// Persistent entry in the service table.
#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
pub struct ServiceMeta {
    pub id: u32,
    pub state: ServiceState,
    pub code_hash: [u8; 32],
}

/// Persistent service table — tracks which services exist, their state, and code hashes.
/// Designed for rkyv serialization so the agent can persist it across invocations.
#[derive(Debug, Clone, rkyv::Archive, rkyv::Serialize, rkyv::Deserialize)]
#[rkyv(crate = rkyv)]
pub struct ServiceTable<const N: usize> {
    entries: [Option<ServiceMeta>; N],
    count: u32,
}

impl<const N: usize> Default for ServiceTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> ServiceTable<N> {
    const NONE: Option<ServiceMeta> = None;

    pub fn new() -> Self {
        Self {
            entries: [Self::NONE; N],
            count: 0,
        }
    }

    /// Register a new service with a code hash. Returns its ID, or `None` if full.
    pub fn register(&mut self, code_hash: [u8; 32]) -> Option<ServiceId> {
        if self.count as usize >= N {
            return None;
        }
        self.count += 1;
        let id = ServiceId(self.count);
        let idx = (id.0 - 1) as usize;
        self.entries[idx] = Some(ServiceMeta {
            id: id.0,
            state: ServiceState::Created,
            code_hash,
        });
        Some(id)
    }

    pub fn get(&self, id: ServiceId) -> Option<&ServiceMeta> {
        let idx = id.0.checked_sub(1)? as usize;
        self.entries.get(idx)?.as_ref()
    }

    pub fn get_mut(&mut self, id: ServiceId) -> Option<&mut ServiceMeta> {
        let idx = id.0.checked_sub(1)? as usize;
        self.entries.get_mut(idx)?.as_mut()
    }

    pub fn update_state(&mut self, id: ServiceId, state: ServiceState) {
        if let Some(entry) = self.get_mut(id) {
            entry.state = state;
        }
    }

    pub fn alive_count(&self) -> usize {
        self.entries
            .iter()
            .filter(|e| {
                e.as_ref()
                    .is_some_and(|m| m.state != ServiceState::Stopped)
            })
            .count()
    }

    /// Iterate over all alive service entries.
    pub fn iter_alive(&self) -> impl Iterator<Item = &ServiceMeta> {
        self.entries.iter().filter_map(|e| {
            e.as_ref()
                .filter(|m| m.state != ServiceState::Stopped)
        })
    }
}

