//! Runtime-behaviour probe actor for VOS core regression tests.
//!
//! Each handler exercises one host-side invariant the `elf_integration`
//! suite pins:
//!
//! - [`ping`](Probe::ping) — increments `seen` and yields mid-handler,
//!   so a batch of several `ping`s must be delivered across ticks
//!   without dropping the un-fetched remainder.
//! - [`seen`](Probe::seen) — reads back the delivered count.
//! - [`boom`](Probe::boom) — asks a child (which journals a write via
//!   its cold-start hook), then traps; the host must discard the whole
//!   dispatch — the absorbed child write included — so a panicked
//!   handler commits nothing.

use vos::abi::service::ServiceId;
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

    /// Ask `child` (a leaker, whose cold-start hook journals a write into
    /// this dispatch), then trap. The absorbed child write must be
    /// discarded with the rest of the panicked dispatch — nothing commits.
    #[msg]
    async fn boom(&mut self, ctx: &mut Context<Self>, child: u32) {
        let _ = ctx.ask(ServiceId(child), &Msg::new("start")).await;
        panic!("boom: discard-on-panic regression");
    }

    /// Ask `child` and return normally — the baseline companion to
    /// `boom`. The child's absorbed write commits when this dispatch
    /// completes, proving the discard test isn't vacuous.
    #[msg]
    async fn relay(&mut self, ctx: &mut Context<Self>, child: u32) {
        let _ = ctx.ask(ServiceId(child), &Msg::new("start")).await;
    }

    /// Fire a fire-and-forget transfer at `target`. When `target` is not
    /// a service in this runtime it becomes an external transfer the node
    /// routes through its outbox — used to pin commit-then-outbox order.
    #[msg]
    async fn tell_out(&mut self, ctx: &mut Context<Self>, target: u32) {
        ctx.tell(ServiceId(target), &Msg::new("noop"));
    }
}
