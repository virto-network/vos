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

    /// Resolve `name` by invoking the registry actor at
    /// `ServiceId::REGISTRY` directly: it's a regular vos
    /// service with a `resolve(name) -> u32` message, and
    /// `ctx.ask` is how any actor talks to any other.
    /// Returns the matching ServiceId, or 0 when unregistered.
    /// Will be sugared to `RegistryActorClient::at(ctx).resolve(name).await`
    /// once `#[messages]` learns to emit per-actor client traits.
    #[msg]
    async fn whois(&self, ctx: &mut Context<Self>, name: String) -> u32 {
        use vos::abi::service::ServiceId;
        let msg = vos::value::Msg::new("resolve").with("name", name.clone());
        match ctx.ask(ServiceId::REGISTRY, &msg).await {
            Ok(value) => {
                let id = value.as_u32().unwrap_or(0);
                if id == 0 {
                    println!("crdt-counter: whois({name}) -> not found");
                } else {
                    println!("crdt-counter: whois({name}) -> {id}");
                }
                id
            }
            Err(e) => {
                println!("crdt-counter: whois({name}) -> error {e:?}");
                0
            }
        }
    }
}
