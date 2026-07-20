//! CRDT counter — a minimal actor whose state replicates across
//! nodes via the merkle-CRDT machinery.
//!
//! Two messages:
//!   - `inc()` increments the CRDT counter by one. Its operation id comes
//!     from the stable invocation id supplied by the runtime, so concurrent
//!     replicas keep both increments and replay remains idempotent.
//!   - `get() -> u64` reports the current count (read-only →
//!     no DAG node, see `crdt_commit_skips_unchanged_plain_commits`).
//!
//! Replication shape: each `inc()` is recorded as a durable CRDT
//! event and materialized through [`crdt::Counter`], rather than a
//! plain mutable scalar.

use vos::prelude::*;
#[actor(crdt)]
pub struct CrdtCounter {
    count: crdt::Counter,
}

impl CrdtCounter {
    fn apply_increment(&mut self) {
        // The service allocates a stable change scope for the complete actor
        // slice; each field mutation receives its next operation ordinal.
        if self.count.increment(1).is_err() {
            panic!("crdt-counter: divergent operation id");
        }
    }
}

#[messages]
impl CrdtCounter {
    fn new() -> Self {
        CrdtCounter {
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

    /// Deliberate panic for failure-mode tests. The runtime
    /// should surface this to the caller as
    /// `InvokeError::Panicked`, leave the actor's state
    /// intact, and continue dispatching subsequent messages
    /// — the next `inc()` after a `boom()` must work.
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
