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
    fn apply_increment(&mut self, invocation_id: InvocationId) {
        let id = crdt::ChangeId::from(invocation_id).operation(0);
        // Reapplying the same durable event is idempotent. A divergent reuse
        // is a runtime invariant violation and must not silently mutate state.
        if self.count.increment(id, 1).is_err() {
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
    async fn inc(&mut self, ctx: &mut Context<Self>) {
        self.apply_increment(ctx.invocation_id());
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
        let mut left_ctx: Context<CrdtCounter> = Context::new(vos::actors::context::ServiceId(1));
        let mut right_ctx: Context<CrdtCounter> = Context::new(vos::actors::context::ServiceId(1));
        left_ctx.__set_invocation_id(InvocationId::derive(b"test-replica", b"left"));
        right_ctx.__set_invocation_id(InvocationId::derive(b"test-replica", b"right"));

        left.apply_increment(left_ctx.invocation_id());
        right.apply_increment(right_ctx.invocation_id());
        left.count.merge(&right.count).expect("counter merge");

        assert_eq!(left.count.value(), 2);
    }
}
