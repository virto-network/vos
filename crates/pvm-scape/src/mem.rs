//! Memory management — sbrk-based heap for no_std actors.
//!
//! PVM programs get a linear memory with a growable heap region.
//! The javm runtime handles `sbrk` via the host-call mechanism.
//! This module provides a minimal allocator interface.

/// Current break pointer (end of heap). Managed by the runtime.
static mut BRK: usize = 0;

/// Simple bump allocator for PVM programs.
/// Not a full GlobalAlloc — just enough for basic needs.
///
/// In practice, child actors that use `std` will have the allocator
/// provided by the c-scape / pvm-scape integration layer. This is
/// the low-level building block for that.
///
/// # Safety
///
/// Must only be called from single-threaded PVM execution context.
/// The caller must ensure `increment` does not exceed available heap space.
#[inline]
pub unsafe fn sbrk(increment: usize) -> *mut u8 {
    unsafe {
        let old_brk = BRK;
        BRK += increment;
        old_brk as *mut u8
    }
}
