//! Contract-compatible replacement used by the physical upgrade gate.

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
        self.value = self.value.saturating_add(by);
        self.value
    }

    #[msg]
    fn value(&self) -> u64 {
        self.value
    }
}
