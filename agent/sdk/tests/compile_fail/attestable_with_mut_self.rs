use vos_sdk::prelude::*;

#[actor]
pub struct Counter {
    entries: CommittedMap<u32, u64>,
}

#[messages]
impl Counter {
    #[attestable]
    pub fn writes(&mut self, key: u32) -> u64 {
        self.entries.insert(&key, &1);
        1
    }
}

fn main() {}
