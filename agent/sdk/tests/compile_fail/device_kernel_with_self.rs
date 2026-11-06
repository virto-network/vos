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

    /// A device reads no root: a device kernel takes no `self`.
    #[attestable(device, reference = reference)]
    pub fn entry(&self, key: u32) -> u64 {
        self.entries.get(&key).unwrap_or(0)
    }
}

fn reference() {}

fn main() {}
