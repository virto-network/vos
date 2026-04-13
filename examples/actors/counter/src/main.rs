//! Counter actor — increments and prints a count each iteration.
//!
//! Demonstrates a stateful refine-only actor with a yield loop.
//! Each invocation runs one iteration: increment, print, yield.
//! The agent re-invokes to drive subsequent iterations.

use vos::{actor, messages};

#[actor]
struct Counter {
    count: u32,
}

#[messages]
impl Counter {
    fn new() -> Self {
        Counter { count: 0 }
    }

    #[msg]
    async fn start(&mut self, ctx: &mut Context<Self>) {
        loop {
            self.count += 1;
            println!("counter: count = {}", self.count);
            ctx.yield_now().await;
        }
    }
}
