//! Tally — a witness-delivered **Task** actor (`#[actor(task)]`).
//!
//! The canonical `Child::Task` fixture: input arrives as `(state, msg)`
//! patched into the `__VOS_WITNESS` buffer, no READ/FETCH, one message
//! per invocation, state travels through the parent's TaskRecord. The
//! live≡traced gate in `vos/tests/elf_integration.rs` runs this blob
//! both ways and asserts byte-identical images and work-results.

use vos::prelude::*;

#[actor(task)]
struct Tally {
    total: u64,
    steps: u32,
}

#[messages]
impl Tally {
    fn new() -> Self {
        Tally { total: 0, steps: 0 }
    }

    /// One-shot: fold `n` into the running total and reply with it.
    #[msg]
    async fn add(&mut self, n: u64) -> u64 {
        self.total += n;
        self.total
    }

    /// Multi-step job: each invocation performs one step and yields
    /// until three steps are done — the suspended task is its
    /// TaskRecord, and the parent's drive passes deliver this same
    /// message with the saved state until completion.
    #[msg]
    async fn work(&mut self, ctx: &mut Context<Self>) -> u64 {
        self.steps += 1;
        self.total += u64::from(self.steps);
        if self.steps < 3 {
            ctx.yield_now().await;
        }
        self.total
    }
}
