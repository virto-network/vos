//! CRDT counter — a minimal actor whose state replicates across
//! nodes via the merkle-CRDT machinery.
//!
//! Two messages:
//!   - `inc()` increments the count by one. Two replicas calling
//!     this concurrently produce distinct DAG nodes (and so the
//!     merge surfaces both events) because the runtime stamps
//!     each event with `(origin, seq)` — see
//!     [`vos::effect_log::CrdtEvent`]. Handlers don't see those
//!     fields; they're metadata for CID stability.
//!   - `get() -> u64` reports the current count (read-only →
//!     no DAG node, see `crdt_commit_skips_unchanged_plain_commits`).
//!
//! Replication shape: each `inc()` is recorded as an EffectLog
//! tagged with the producing replica's origin+seq. Replicas that
//! see the same set of logs converge to the same count regardless
//! of order, since the underlying op is commutative.

use vos::prelude::*;
#[actor]
pub struct CrdtCounter {
    count: u64,
}

#[messages]
impl CrdtCounter {
    fn new() -> Self {
        CrdtCounter { count: 0 }
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

    /// Deliberate panic for failure-mode tests. The runtime
    /// should surface this to the caller as
    /// `InvokeError::Panicked`, leave the actor's state
    /// intact, and continue dispatching subsequent messages
    /// — the next `inc()` after a `boom()` must work.
    #[msg]
    async fn boom(&self) {
        panic!("crdt-counter: boom — deliberate panic for test");
    }

    /// Resolve `name` against the per-space registry via the
    /// `Context::resolve` utility. No dep on space-registry's
    /// typed Ref — `ctx.resolve` sends a dynamic message to
    /// the well-known `ServiceId::REGISTRY` and returns the
    /// asking node's local svc_id (or 0 if not installed).
    #[msg]
    async fn whois(&self, ctx: &mut Context<Self>, name: String) -> u32 {
        let id = ctx.resolve(name.clone()).await;
        if id == 0 {
            log::info!("crdt-counter: whois({name}) -> not found");
        } else {
            log::info!("crdt-counter: whois({name}) -> {id}");
        }
        id
    }
}
