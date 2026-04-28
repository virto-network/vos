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

use vos::{actor, messages};

#[actor]
struct CrdtCounter {
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
        println!("crdt-counter: inc tag={tag} -> count={}", self.count);
    }

    #[msg]
    async fn get(&self) -> u64 {
        println!("crdt-counter: get -> {}", self.count);
        self.count
    }

    /// Resolve `name` against the hyperspace registry via the
    /// cycle-9 phase-3 `ctx.resolve` sugar. Returns the full
    /// 32-bit ServiceId of the matching service, or 0 when the
    /// name isn't registered. Lets integration tests verify the
    /// runtime-lookup path through a real PVM actor.
    #[msg]
    async fn whois(&self, ctx: &mut Context<Self>, name: String) -> u32 {
        match ctx.resolve(&name) {
            Some(id) => {
                println!("crdt-counter: whois({name}) -> {}", id.0);
                id.0
            }
            None => {
                println!("crdt-counter: whois({name}) -> not found");
                0
            }
        }
    }
}
