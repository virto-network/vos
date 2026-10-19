use vos_sdk::prelude::*;

#[actor]
pub struct Counter {
    notes: Table<u32, u64>,
    entries: CommittedMap<u32, u64>,
}

#[messages]
impl Counter {
    pub fn new() -> Self {
        Self {
            notes: Table::default(),
            entries: CommittedMap::default(),
        }
    }

    /// A table is no committed map: no root proves its rows.
    #[attestable]
    pub fn reads_a_table(&self, key: u32) -> Option<u64> {
        self.notes.get(&key)
    }
}

fn main() {}
