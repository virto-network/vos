//! Greeter actor — one-shot actor that prints a greeting and exits.
//!
//! Demonstrates the simplest refine-only actor: a single `run()` handler
//! that executes once and completes.

use vos::{actor, messages};

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
    async fn run(&self, _ctx: &mut Context<Self>) {
        println!("Hello n={}", self.n);
    }
}
