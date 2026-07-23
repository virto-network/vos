//! CRDT counter — a minimal actor whose state replicates across
//! nodes via the merkle-CRDT machinery.
//!
//! Two messages:
//!   - `inc()` increments the CRDT counter by one. The current
//!     command-replay bridge applies each durable event in canonical
//!     causal order, so the visible count supplies the operation ordinal.
//!     The v2 operation-capture runtime replaces this bridge with
//!     invocation-derived operation IDs.
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

#[messages]
impl CrdtCounter {
    fn new() -> Self {
        CrdtCounter {
            count: crdt::Counter::default(),
        }
    }

    #[msg]
    async fn inc(&mut self) {
        let current = self.count.value();
        let id = crdt::ChangeId::derive(b"crdt-counter/inc", &current.to_le_bytes()).operation(0);
        // Reapplying the same durable event is idempotent. A divergent reuse
        // is a runtime invariant violation and must not silently mutate state.
        if self.count.increment(id, 1).is_err() {
            panic!("crdt-counter: divergent operation id");
        }
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
}
