//! CRDT counter — a minimal actor whose state replicates across
//! nodes via the cycle-3/4 merkle-CRDT machinery.
//!
//! Two messages:
//!   - `inc(tag: u32)` increments the count by one. The `tag`
//!     parameter is part of the EffectLog payload, so callers
//!     using different tags produce different DAG-node CIDs —
//!     necessary because the merkle-DAG content-addresses
//!     events and would otherwise dedup byte-identical incs
//!     coming from concurrent replicas. Use a per-replica
//!     unique tag (or a monotone source counter) when driving
//!     it; for unit tests, simple integers suffice.
//!   - `get() -> u64` reports the current count (read-only →
//!     no DAG node, see `crdt_commit_skips_unchanged_plain_commits`).
//!
//! Replication shape: each `inc(tag)` is recorded as an
//! EffectLog. Replicas that see the same set of logs converge
//! to the same count regardless of order, since the underlying
//! op is commutative.

#![cfg_attr(any(target_arch = "riscv64", target_arch = "wasm32"), no_std)]
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
    async fn inc(&mut self, tag: u32) {
        // `tag` is in the EffectLog so concurrent incs from different
        // replicas hash to different DAG-node CIDs. Not used in the
        // state transition.
        self.count += 1;
        log::info!("crdt-counter: inc tag={tag} -> count={}", self.count);
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

    /// Resolve `name` against the hyperspace registry via the
    /// macro-generated `RegistryRef`. The same Ref type works
    /// here (with `ctx` as the invoker) and from host code (with
    /// `&node` as the invoker).
    #[msg]
    async fn whois(&self, ctx: &mut Context<Self>, name: String) -> u32 {
        use vos::abi::service::ServiceId;
        use registry::RegistryRef;
        match RegistryRef::at(ServiceId::REGISTRY).resolve(ctx, name.clone()).await {
            Ok(id) => {
                if id == 0 {
                    log::info!("crdt-counter: whois({name}) -> not found");
                } else {
                    log::info!("crdt-counter: whois({name}) -> {id}");
                }
                id
            }
            Err(e) => {
                log::info!("crdt-counter: whois({name}) -> error {e}");
                0
            }
        }
    }
}

