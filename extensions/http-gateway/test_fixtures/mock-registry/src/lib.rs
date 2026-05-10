//! Stand-in for the bundled space-registry, used by the
//! http-gateway dispatch tests. Only implements the one
//! handler the gateway calls (`resolve(name) -> u32`); the actor
//! itself is a hardcoded `(name → ServiceId)` map.
//!
//! Built as a real `.so` so it loads through the same
//! ExtensionPlugin path the production registry would (when the
//! production registry exists as an extension at all).
//!
//! Mappings (matched in tests/common.rs to the fixture install
//! order — REGISTRY = 0, then `counter` at id 1, then
//! `kitchen` at id 2):
//!   "counter" → 1
//!   "kitchen" → 2
//!   _         → 0  (gateway treats 0 as "unknown" → 404)

use vos::prelude::*;

#[actor]
#[derive(Default)]
pub struct MockRegistry;

#[messages]
impl MockRegistry {
    fn new() -> Self {
        Self
    }

    #[msg]
    async fn resolve(&self, name: String, _ctx: &mut Context<Self>) -> u32 {
        match name.as_str() {
            "counter" => 1,
            "kitchen" => 2,
            _ => 0,
        }
    }
}
