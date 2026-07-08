//! Effect-on-invoke child actor for the discard-on-panic regression.
//!
//! Its `start` handler runs on every cold invoke (a child INVOKE always
//! cold-starts) and emits a single storage write. When a parent asks a
//! leaker inside a dispatch that later traps, the host must discard the
//! absorbed write; when the parent returns normally, the write commits.

use vos::prelude::*;

/// Storage key the `start` handler writes. The discard-on-panic test
/// asserts it never reaches the leaker's row when the asking parent traps.
pub const LEAK_KEY: &[u8] = b"leaker_mark";

#[actor]
struct Leaker {
    invoked: u32,
}

#[messages]
impl Leaker {
    fn new() -> Self {
        Leaker { invoked: 0 }
    }

    /// Cold-start hook — emits the write the parent's dispatch absorbs.
    #[msg]
    async fn start(&mut self, ctx: &mut Context<Self>) {
        self.invoked += 1;
        ctx.store(LEAK_KEY, b"1");
    }
}
