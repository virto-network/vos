//! Legacy v1 CRDT transport fixture.
//!
//! The production v1 runtime replicates ordinary actor state by replaying
//! effect logs. It does not provide the slice-scoped operation allocator used
//! by `#[actor(crdt)]` in v2, so this fixture intentionally remains a plain
//! counter and must not be used as a public v2 example.

use vos::prelude::*;

#[actor]
pub struct CrdtCounter {
    count: u64,
}

#[messages]
impl CrdtCounter {
    fn new() -> Self {
        Self { count: 0 }
    }

    #[msg]
    async fn inc(&mut self) {
        self.count += 1;
        log::info!("crdt-counter: inc -> count={}", self.count);
    }

    #[msg]
    async fn get(&self) -> u64 {
        log::info!("crdt-counter: get -> {}", self.count);
        self.count
    }

    #[msg]
    async fn boom(&self) {
        panic!("crdt-counter: boom — deliberate panic for test");
    }
}
