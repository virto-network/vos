//! Poseidon2-M31 compressions through the guest precompile shim
//! (`vos-pvm-precompiles`), which calls the VOS precompile (`ecalli 0x402`)
//! and falls back to software when the host answers `WHAT`, as a JAM node
//! does for an id it does not assign. Compress `n` times, feeding each
//! output into the next call's left half. Argument: n as a little-endian
//! u64. Output: the last output's 32 bytes.

#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;

use vos_pvm_precompiles::poseidon2_compress;

global_asm!(
    ".global _start",
    ".type _start, @function",
    "_start:",
    "mv s0, ra",
    "jal ra, hash_main",
    "mv ra, s0",
    "ret",
);

struct Out(UnsafeCell<[u32; 8]>);

// SAFETY: a PVM invocation is single-threaded.
unsafe impl Sync for Out {}

static OUT: Out = Out(UnsafeCell::new([0; 8]));

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
    let right = [9u32, 8, 7, 6, 5, 4, 3, 2];
    let mut left = [7u32; 8];
    for _ in 0..n {
        left = poseidon2_compress(&left, &right);
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
