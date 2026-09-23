//! Required-constructor fixture for external-state lifecycle qualification.
use vos::prelude::*;
use vos::storage::StorageMap;

#[actor(agent)]
pub struct AgentStateActor {
    #[state(linear)]
    value: u64,
    #[storage(linear, prefix = "s/rows/")]
    rows: StorageMap<u64, u64>,
}

#[messages(agent)]
impl AgentStateActor {
    fn new(seed: u64) -> Self {
        Self {
            value: seed,
            rows: StorageMap::default(),
        }
    }

    #[msg(linear)]
    fn advance(&mut self) -> u64 {
        self.value += 1;
        self.rows.insert(&0, &self.value);
        self.rows.get(&0).unwrap()
    }

    #[msg(linearizable)]
    fn stored(&self) -> u64 {
        self.rows.get(&0).unwrap_or(u64::MAX)
    }
}
