//! Trapping child for the too-big-vs-crash regression.
//!
//! Its cold-start hook executes an illegal instruction, so the child
//! traps during an ask and the host reports `STATUS_PANICKED` — the crash
//! case an oversize reply must stay distinct from.

use vos::prelude::*;

#[actor]
struct Crasher;

#[messages]
impl Crasher {
    fn new() -> Self {
        Crasher
    }

    #[msg]
    async fn start(&mut self, _ctx: &mut Context<Self>) {
        // SAFETY: `unimp` is an illegal instruction — it deterministically
        // traps the guest so the host reports a crash, with no dependence
        // on which addresses happen to be mapped.
        unsafe {
            core::arch::asm!("unimp");
        }
    }
}
