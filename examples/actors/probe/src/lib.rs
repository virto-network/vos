//! Runtime-behaviour probe actor for VOS core regression tests.
//!
//! Each handler exercises one host-side invariant the `elf_integration`
//! suite pins:
//!
//! - [`ping`](Probe::ping) — increments `seen` and yields mid-handler,
//!   so a batch of several `ping`s must be delivered across ticks
//!   without dropping the un-fetched remainder.
//! - [`seen`](Probe::seen) — reads back the delivered count.

use vos::prelude::*;

#[actor]
struct Probe {
    seen: u32,
}

#[messages]
impl Probe {
    fn new() -> Self {
        Probe { seen: 0 }
    }

    /// Count this message, then yield. A batch of `ping`s therefore
    /// consumes one message per tick: the host must re-queue the mail
    /// the guest had not yet FETCHed before it yielded.
    #[msg]
    async fn ping(&mut self, ctx: &mut Context<Self>) {
        self.seen += 1;
        ctx.yield_now().await;
    }

    /// Number of `ping`s delivered so far.
    #[msg]
    async fn seen(&self) -> u32 {
        self.seen
    }
}
