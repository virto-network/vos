//! BLAKE2b-256 inside the PVM: hash a 76-byte node input (a 12-byte domain
//! and two 32-byte children) `n` times, chaining each output into the next
//! input. Argument: n as a little-endian u64. Output: the final hash.

#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;

global_asm!(
    ".global _start",
    ".type _start, @function",
    "_start:",
    "mv s0, ra",
    "jal ra, hash_main",
    "mv ra, s0",
    "ret",
);

struct Out(UnsafeCell<[u8; 32]>);

// SAFETY: a PVM invocation is single-threaded.
unsafe impl Sync for Out {}

static OUT: Out = Out(UnsafeCell::new([0; 32]));

#[repr(C)]
pub struct Output {
    address: u64,
    len: u64,
}

#[unsafe(no_mangle)]
extern "C" fn hash_main(arguments: *const u8, len: u64) -> Output {
    // SAFETY: the host maps the argument window read-only at (a0, a1).
    let arguments = unsafe { core::slice::from_raw_parts(arguments, len as usize) };
    let n = u64::from_le_bytes(arguments[..8].try_into().unwrap());
    let mut left = [7u8; 32];
    let right = [9u8; 32];
    for _ in 0..n {
        let hash = blake2b_simd::Params::new()
            .hash_length(32)
            .to_state()
            .update(b"vos/smt/node")
            .update(&left)
            .update(&right)
            .finalize();
        left.copy_from_slice(hash.as_bytes());
    }
    // SAFETY: single-threaded; the host reads the output after halt.
    unsafe { *OUT.0.get() = left };
    Output {
        address: OUT.0.get() as u64,
        len: 32,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: `unimp` lowers to a PVM trap.
    unsafe { asm!("unimp", options(noreturn)) }
}
