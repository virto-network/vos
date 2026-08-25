//! Explicit CRDT installation fixture.
//!
//! This retains the former public CRDT counter for registry and package gates.
//! It is deliberately separate from the plain legacy-v1 replay fixture.

use vos::prelude::*;

#[actor(crdt)]
pub struct CrdtCounter {
    count: crdt::Counter,
}

impl CrdtCounter {
    fn apply_increment(&mut self) {
        self.count
            .increment(1)
            .expect("actor dispatch establishes a CRDT change scope");
    }
}

#[messages]
impl CrdtCounter {
    fn new() -> Self {
        Self {
            count: crdt::Counter::default(),
        }
    }

    #[msg]
    async fn inc(&mut self) {
        self.apply_increment();
        log::info!("crdt-counter: inc -> count={}", self.count.value());
    }

    #[msg]
    async fn get(&self) -> u64 {
        let count = self.count.value().max(0) as u64;
        log::info!("crdt-counter: get -> {count}");
        count
    }

    #[msg]
    async fn boom(&self) {
        panic!("crdt-counter: boom — deliberate panic for test");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn program_declares_crdt_storage() {
        assert!(<CrdtCounter as vos::Actor>::CRDT);
    }

    #[test]
    fn concurrent_increments_from_the_same_value_both_survive_merge() {
        let mut left = CrdtCounter::new();
        let mut right = CrdtCounter::new();

        crdt::with_change(
            crdt::ChangeId::from(InvocationId::derive(b"test-replica", b"left")),
            || {
                left.apply_increment();
                Ok(())
            },
        )
        .unwrap();
        crdt::with_change(
            crdt::ChangeId::from(InvocationId::derive(b"test-replica", b"right")),
            || {
                right.apply_increment();
                Ok(())
            },
        )
        .unwrap();
        left.count.merge(&right.count).expect("counter merge");

        assert_eq!(left.count.value(), 2);
    }
}
