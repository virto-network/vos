//! BLAKE2b-256 through the guest precompile shim (`vos-pvm-precompiles`),
//! which calls the VOS compression precompile (`ecalli 0x400`) and falls
//! back to software when the host answers `WHAT`, as a JAM node does for an
//! id it does not assign. Same chain as the `hash-software` guest: hash a
//! 76-byte node input `n` times, feeding each output into the next input.

#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;

use vos_pvm_precompiles::blake2b_hash;

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
    let right = [9u8; 32];
    let mut left = [7u8; 32];
    for _ in 0..n {
        left = blake2b_hash::<32>(b"vos/smt/node", &[&left, &right]);
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
