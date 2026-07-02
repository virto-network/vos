//! Settlement-verifier ELF for the JAM PVM (riscv64em-javm).
//!
//! A `#![no_main]` binary whose `_start` deserializes an embedded Poseidon2-M31
//! `StarkProof` fixture and runs the full verify path
//! ([`recursion_verifier::verify_settlement_proof`] and its transitive graph —
//! FRI verify, Merkle decommit, OODS composition re-eval), halting with the
//! result. This is the end-to-end proof that the M31-algebraic settlement verify
//! is PVM-runnable AND value-correct: it ACCEPTS the honest fixture on the JAM
//! PVM (see `zkpvm/tests/settle_run.rs`).
//!
//! Built only with `--features pvm-settle` (so host / wasm32 `cargo build`
//! skips the bare-metal bin).
#![no_std]
#![no_main]

extern crate alloc;

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::panic::PanicInfo;
/// Bump allocator over a 16-aligned static arena (single-core ⇒ no locking).
/// Frees are no-ops; sized so the verify's allocation never exhausts it before
/// the run ends (proven: 192 MiB and 512 MiB halt at the identical cycle, so the
/// run is NOT allocator-bound).
const ARENA_BYTES: usize = 192 << 20;

#[repr(align(16))]
struct Arena([u8; ARENA_BYTES]);

struct Bump {
    arena: UnsafeCell<Arena>,
    next: UnsafeCell<usize>,
}
unsafe impl Sync for Bump {}

unsafe impl GlobalAlloc for Bump {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let base = (*self.arena.get()).0.as_mut_ptr();
        let off = *self.next.get();
        let misalign = base.add(off) as usize & (layout.align() - 1);
        let pad = if misalign == 0 { 0 } else { layout.align() - misalign };
        let start = off + pad;
        let end = start + layout.size();
        if end > ARENA_BYTES {
            return core::ptr::null_mut();
        }
        *self.next.get() = end;
        base.add(start)
    }
    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ALLOC: Bump = Bump {
    arena: UnsafeCell::new(Arena([0; ARENA_BYTES])),
    next: UnsafeCell::new(0),
};

/// The settlement proof, produced + format-pinned host-side by
/// `zkpvm/tests/settle_fixture.rs` (postcard-encoded `StarkProof<P2MerkleHasher>`
/// of the trivial boolean AIR).
const FIXTURE: &[u8] = include_bytes!("../../fixtures/bool_proof.postcard");

/// Halt with `code` in `a0`, then `unimp` (illegal ⇒ JAVM stops).
///   0xACCE = accepted · 0x5E5 = rejected · 0xDEAD = internal panic
#[inline(never)]
fn halt(code: u64) -> ! {
    unsafe {
        core::arch::asm!("mv a0, {c}", "unimp", c = in(reg) code, options(noreturn, nostack));
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    halt(0xDEAD)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // Deserialize the embedded proof and run the full Poseidon2-M31 verify
    // (FRI + Merkle decommit + OODS) on the PVM.
    match recursion_verifier::verify_settlement_proof(FIXTURE) {
        Ok(()) => halt(0xACCE),  // accepted
        Err(()) => halt(0x5E5),  // rejected
    }
}
