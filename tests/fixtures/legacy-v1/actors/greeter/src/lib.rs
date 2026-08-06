//! Greeter actor — one-shot actor that prints a greeting and exits.
//!
//! Demonstrates the simplest refine-only actor: a single `start()` handler
//! that executes once and completes.

use vos::prelude::*;
#[actor]
struct Greeter {
    n: u32,
}

#[messages]
impl Greeter {
    fn new() -> Self {
        Greeter { n: 42 }
    }

    #[msg]
    async fn start(&self, _ctx: &mut Context<Self>) {
        log::info!("greeter: Hello n={}", self.n);
    }

    #[msg]
    async fn origin_kind(&self, ctx: &mut Context<Self>) -> u8 {
        match ctx.origin() {
            vos::v2::Origin::Anonymous => 0,
            vos::v2::Origin::Member(_) => 1,
            vos::v2::Origin::Actor(_) => 2,
            vos::v2::Origin::System => 3,
        }
    }
}
