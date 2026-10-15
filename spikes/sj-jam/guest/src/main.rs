//! Minimal Gray Paper 0.8.0 service built with the VOS toolchain.
//!
//! Refine returns `vos:` followed by its work-item payload. Accumulate stores
//! the encoding of its first input under the storage key `last`.

#![no_std]
#![no_main]

use core::arch::{asm, global_asm};

// IC 0 is Refine and IC 5 is Accumulate; the linker emits that prologue from
// these two exported symbols. The host installs the halt address in `ra`, so
// returning from either entry halts with the output window in a0/a1.
global_asm!(
    ".global _start",
    ".type _start, @function",
    "_start:",
    "mv s0, ra",
    "jal ra, sj_refine",
    "mv ra, s0",
    "ret",
    ".global accumulate",
    ".type accumulate, @function",
    "accumulate:",
    "mv s0, ra",
    "jal ra, sj_accumulate",
    "mv ra, s0",
    "ret",
);

const FETCH: u64 = 2;
const WRITE: u64 = 5;
const LOG: u64 = 100;
const NONE: u64 = u64::MAX;

/// Fetch kind for one accumulate input, `E(i[φ11])`.
const FETCH_INPUT: u64 = 15;

#[repr(C)]
pub struct Output {
    address: u64,
    len: u64,
}

static mut BUFFER: [u8; 8192] = [0; 8192];

macro_rules! hostcall {
    ($id:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {{
        let result: u64;
        // SAFETY: the standard ecalli convention passes arguments in a0..a4
        // and returns in a0. Pointer arguments name live guest buffers, and
        // the host may write them, so memory is not marked read-only.
        unsafe {
            asm!(
                "li t0, {id}",
                "csrw 0x801, zero",
                "ecall",
                id = const $id,
                lateout("t0") _,
                inlateout("a0") $a0 as u64 => result,
                inlateout("a1") $a1 as u64 => _,
                inlateout("a2") $a2 as u64 => _,
                inlateout("a3") $a3 as u64 => _,
                inlateout("a4") $a4 as u64 => _,
                options(nostack),
            );
        }
        result
    }};
}

fn log(message: &[u8]) {
    let target = b"vos-sj";
    hostcall!(
        LOG,
        2u64,
        target.as_ptr(),
        target.len(),
        message.as_ptr(),
        message.len()
    );
}

/// Gray Paper natural decoding (appendix C): the count of leading one bits in
/// the first byte is the number of little-endian bytes that follow.
fn decode_natural(bytes: &[u8]) -> Option<(u64, &[u8])> {
    let (&first, rest) = bytes.split_first()?;
    let extra = first.leading_ones() as usize;
    if extra == 8 {
        let value = u64::from_le_bytes(rest.get(..8)?.try_into().ok()?);
        return Some((value, &rest[8..]));
    }
    let tail = rest.get(..extra)?;
    let mut value = u64::from(first & (0xff >> (extra + 1))) << (8 * extra);
    for (index, byte) in tail.iter().enumerate() {
        value |= u64::from(*byte) << (8 * index);
    }
    Some((value, &rest[extra..]))
}

fn buffer() -> &'static mut [u8; 8192] {
    // SAFETY: a PVM invocation is single-threaded and each entry takes the
    // buffer exactly once.
    unsafe { &mut *core::ptr::addr_of_mut!(BUFFER) }
}

/// Refine arguments: `E(c, i, s, ↕payload, H(p))`.
#[unsafe(no_mangle)]
extern "C" fn sj_refine(arguments: *const u8, len: u64) -> Output {
    // SAFETY: the host maps the argument window read-only at (a0, a1).
    let arguments = unsafe { core::slice::from_raw_parts(arguments, len as usize) };
    log(b"refine");
    let payload = decode_natural(arguments)
        .and_then(|(_, rest)| decode_natural(rest))
        .and_then(|(_, rest)| decode_natural(rest))
        .and_then(|(_, rest)| decode_natural(rest))
        .and_then(|(length, rest)| rest.get(..length as usize))
        .unwrap_or(b"?");
    let out = buffer();
    out[..4].copy_from_slice(b"vos:");
    let n = payload.len().min(out.len() - 4);
    out[4..4 + n].copy_from_slice(&payload[..n]);
    Output {
        address: out.as_ptr() as u64,
        len: (4 + n) as u64,
    }
}

/// Accumulate arguments: `E(t, s, |inputs|)`.
#[unsafe(no_mangle)]
extern "C" fn sj_accumulate(_arguments: *const u8, _len: u64) -> Output {
    log(b"accumulate");
    let out = buffer();
    let length = hostcall!(FETCH, out.as_mut_ptr(), 0u64, out.len(), FETCH_INPUT, 0u64);
    if length != NONE {
        let stored = (length as usize).min(out.len());
        let key = b"last";
        let previous = hostcall!(WRITE, key.as_ptr(), key.len(), out.as_ptr(), stored, 0u64);
        if previous == u64::MAX - 4 {
            log(b"write refused: insufficient balance");
        } else {
            log(b"stored input");
        }
    } else {
        log(b"no input");
    }
    Output { address: 0, len: 0 }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: `unimp` lowers to a PVM trap.
    unsafe { asm!("unimp", options(noreturn)) }
}
