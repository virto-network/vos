//! Oversize-reply child for the child-invoke buffer-cap regression.
//!
//! Its state is a fixed 1 KiB array, so an ask of a bloat child through a
//! smaller output buffer comes back as `STATUS_TOO_BIG` — distinct from a
//! crash — rather than the truncated `STATUS_PANICKED` the fixed 4 KiB
//! wall produced. A fixed array (not a `Vec`) keeps rkyv from allocating a
//! large serialization scratch that would OOM the guest heap first.

use vos::prelude::*;

/// State-array size — comfortably over the tiny output buffer the test
/// invokes it through, so the reply overflows that buffer.
const STATE_BYTES: usize = 1024;

#[actor]
struct Bloat {
    data: [u8; STATE_BYTES],
}

#[messages]
impl Bloat {
    fn new() -> Self {
        Bloat {
            data: [0xCD; STATE_BYTES],
        }
    }

    /// Cold-start hook — keeps the actor valid; the state is already
    /// oversized from `new`.
    #[msg]
    async fn start(&mut self, _ctx: &mut Context<Self>) {
        self.data = [0xCD; STATE_BYTES];
    }
}
