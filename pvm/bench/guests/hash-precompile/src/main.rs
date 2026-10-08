//! BLAKE2b-256 through the VOS compression precompile (`ecalli 0x400`),
//! falling back to software when the host answers `WHAT`, as a JAM node does
//! for an id it does not assign. Same chain as S4's guest: hash a 76-byte
//! node input `n` times, feeding each output into the next input.

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

/// Gray Paper `WHAT`: the host does not know this call.
const WHAT: u64 = u64::MAX - 1;

const IV: [u64; 8] = [
    0x6A09E667F3BCC908,
    0xBB67AE8584CAA73B,
    0x3C6EF372FE94F82B,
    0xA54FF53A5F1D36F1,
    0x510E527FADE682D1,
    0x9B05688C2B3E6C1F,
    0x1F83D9ABFB41BD6B,
    0x5BE0CD19137E2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

fn compress_software(h: &mut [u64; 8], m: &[u64; 16], t: u64, f: bool) {
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&IV);
    v[12] ^= t;
    if f {
        v[14] = !v[14];
    }
    for s in &SIGMA {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

/// One compression: the precompile if the host serves it, else software.
fn compress(h: &mut [u64; 8], m: &[u64; 16], t: u64, f: bool) {
    let answer: u64;
    // SAFETY: h (64 bytes, read and written) and m (128 bytes, read) are
    // live for the call; the host leaves every register but φ[7] unchanged.
    unsafe {
        asm!(
            "li t0, 0x400",
            "csrw 0x801, zero",
            "ecall",
            lateout("t0") _,
            inlateout("a0") h.as_mut_ptr() as u64 => answer,
            in("a1") m.as_ptr() as u64,
            in("a2") t,
            in("a3") f as u64,
            lateout("a4") _,
            lateout("a5") _,
            options(nostack),
        );
    }
    if answer == WHAT {
        compress_software(h, m, t, f);
    }
}

/// BLAKE2b-256 of a single block (input at most 128 bytes).
fn hash_block(input: &[u8]) -> [u8; 32] {
    let mut h = IV;
    h[0] ^= 0x0101_0000 ^ 32;
    let mut block = [0u8; 128];
    block[..input.len()].copy_from_slice(input);
    let mut m = [0u64; 16];
    for (i, word) in m.iter_mut().enumerate() {
        *word = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
    }
    compress(&mut h, &m, input.len() as u64, true);
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&h[i].to_le_bytes());
    }
    out
}

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
    let mut input = [0u8; 76];
    input[..12].copy_from_slice(b"vos/smt/node");
    input[12..44].copy_from_slice(&[7u8; 32]);
    input[44..76].copy_from_slice(&[9u8; 32]);
    let mut left = [7u8; 32];
    for _ in 0..n {
        input[12..44].copy_from_slice(&left);
        left = hash_block(&input);
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
