//! Stand-in for the bundled space-registry, used by the
//! http-gateway service_mode_e2e test. Only implements the one
//! handler the gateway calls (`resolve(name) -> u32`); the actor
//! itself is a hardcoded `(name → ServiceId)` map.
//!
//! Built as a real `.so` so it loads through the same
//! ExtensionPlugin path the production registry would (when the
//! production registry exists as an extension at all). The name
//! → id mapping is fixed at compile time: the test installs the
//! companion counter extension at id 1 and the gateway at id 2,
//! so "counter" → 1 is the only entry.

use vos::prelude::*;

#[actor]
#[derive(Default)]
pub struct MockRegistry;

#[messages]
impl MockRegistry {
    fn new() -> Self {
        Self
    }

    /// The only handler the gateway needs: name → ServiceId.
    /// Returns 0 (the convention the gateway already treats as
    /// "unknown") for anything other than "counter".
    #[msg]
    async fn resolve(&self, name: String, _ctx: &mut Context<Self>) -> u32 {
        match name.as_str() {
            "counter" => 1,
            _ => 0,
        }
    }
}
