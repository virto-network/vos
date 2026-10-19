use vos_sdk::prelude::*;

#[actor]
pub struct Counter {
    entries: CommittedMap<u32, u64>,
}

#[messages]
impl Counter {
    pub fn new() -> Self {
        Self {
            entries: CommittedMap::default(),
        }
    }

    #[attestable]
    pub fn writes(&mut self, key: u32) -> u64 {
        self.entries.insert(&key, &1);
        1
    }
}

fn main() {}
