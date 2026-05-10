//! Test counter actor for the http-gateway service_mode_e2e test.
//! Exposes `inc` (mutating, returns new count) and `get` (query,
//! returns current count). Built as an actor-mode extension so the
//! gateway's `ctx.ask_raw` flow exercises the same wire format a
//! production agent would receive.

use vos::prelude::*;

#[actor]
pub struct Counter {
    count: u32,
}

#[messages]
impl Counter {
    fn new() -> Self {
        Self { count: 0 }
    }

    #[msg]
    async fn inc(&mut self, _ctx: &mut Context<Self>) -> u32 {
        self.count += 1;
        self.count
    }

    #[msg]
    async fn get(&self, _ctx: &mut Context<Self>) -> u32 {
        self.count
    }
}
