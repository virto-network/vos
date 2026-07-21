//! Ordinary state uses Local or Raft consistency without CRDT overhead.

use vos::prelude::*;

#[actor]
pub struct Counter {
    value: u64,
}

#[messages]
impl Counter {
    fn new() -> Self {
        Self { value: 0 }
    }

    #[msg]
    fn increment(&mut self, by: u64) -> u64 {
        self.value += by;
        self.value
    }

    #[msg]
    fn value(&self) -> u64 {
        self.value
    }
}
