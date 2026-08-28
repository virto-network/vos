//! EchoExtension — simple native extension that echoes messages back.
//!
//! Demonstrates an extension using the same `#[actor]`/`#[messages]` DSL
//! as PVM actors but compiled as a native `.so` plugin.

use vos::prelude::*;

#[actor(state_version = 1)]
struct EchoExtension {
    count: u32,
}

#[messages]
impl EchoExtension {
    fn new() -> Self {
        EchoExtension { count: 0 }
    }

    #[msg]
    async fn echo(&mut self, text: String, _ctx: &mut Context<Self>) -> String {
        self.count += 1;
        log::info!("echo-extension: echoing '{text}' (#{})", self.count);
        format!("echo #{}: {text}", self.count)
    }

    #[msg]
    async fn count(&self, _ctx: &mut Context<Self>) -> u32 {
        self.count
    }

    /// Test probe for the host-authenticated native-extension task context.
    #[msg]
    async fn invocation_context(&self, ctx: &mut Context<Self>) -> String {
        let caller = match ctx.caller() {
            vos::Caller::Unauthenticated => "unauthenticated".to_owned(),
            vos::Caller::System => "system".to_owned(),
            vos::Caller::Peer(peer) => format!("peer:{peer:?}"),
            vos::Caller::Member(subject) => format!("member:{:02x}", subject.0[0]),
            vos::Caller::Actor(service) => format!("actor:{}", service.0),
        };
        let role = if ctx.has_space_role(SpaceRole::Admin) {
            "admin"
        } else if ctx.has_space_role(SpaceRole::Developer) {
            "developer"
        } else if ctx.has_space_role(SpaceRole::Member) {
            "member"
        } else if ctx.has_space_role(SpaceRole::Guest) {
            "guest"
        } else {
            "none"
        };
        let invocation = if ctx.invocation_id() == InvocationId::ZERO {
            "zero"
        } else {
            "set"
        };
        format!("{caller}|{}|{invocation}|{role}", ctx.id().0)
    }

    #[msg]
    async fn legacy_state_fingerprint(&self, _ctx: &mut Context<Self>) -> u64 {
        <Self as vos::Actor>::STATE_SCHEMA_LEGACY_FINGERPRINTS[0]
    }
}
