//! A small workload mixing branches, comparisons, signed arithmetic, shifts
//! and memory, for an end-to-end proof of a compiled guest. Argument: a
//! little-endian i64 seed. Output: the result as a little-endian i64.

#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;

global_asm!(
    ".global _start",
    ".type _start, @function",
    "_start:",
    "mv s0, ra",
    "jal ra, diverse_main",
    "mv ra, s0",
    "ret",
);

struct Out(UnsafeCell<[u8; 8]>);

// SAFETY: a PVM invocation is single-threaded.
unsafe impl Sync for Out {}

static OUT: Out = Out(UnsafeCell::new([0; 8]));

#[repr(C)]
pub struct Output {
    address: u64,
    len: u64,
}

/// Keep in sync with `diverse` in `pvm/bench/tests/diverse_proof.rs`.
#[inline(never)]
fn compute(input: &[i64; 16]) -> i64 {
    let mut acc: i64 = 0;
    let mut min = i64::MAX;
    let mut max = i64::MIN;
    for &x in input {
        acc = if x < 0 { acc.wrapping_sub(x) } else { acc.wrapping_add(x) };
        min = min.min(x);
        max = max.max(x);
        let mut bits = 0u32;
        let mut y = x as u64;
        while y != 0 {
            bits += (y & 1) as u32;
            y >>= 1;
        }
        acc = acc.wrapping_add(i64::from(bits));
    }
    acc.wrapping_add(max).wrapping_sub(min)
}

#[unsafe(no_mangle)]
extern "C" fn diverse_main(arguments: *const u8, len: u64) -> Output {
    // SAFETY: the host maps the argument window read-only at (a0, a1).
    let arguments = unsafe { core::slice::from_raw_parts(arguments, len as usize) };
    let seed = i64::from_le_bytes(arguments[..8].try_into().unwrap());
    let mut input = [0i64; 16];
    for (i, value) in input.iter_mut().enumerate() {
        *value = (i as i64 * 7 - 40).wrapping_mul(seed);
    }
    // SAFETY: single-threaded; the host reads the output after halt.
    unsafe { *OUT.0.get() = compute(&input).to_le_bytes() };
    Output {
        address: OUT.0.get() as u64,
        len: 8,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: `unimp` lowers to a PVM trap.
    unsafe { asm!("unimp", options(noreturn)) }
}
