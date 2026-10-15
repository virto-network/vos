//! A ledger actor for measuring invocation overhead.
//!
//! Runs as an inner machine. Its state calls exit to whoever hosts it: the
//! agent program (nested path) or the node directly (fast path). It has no
//! allocator, so a machine can be re-invoked from its entry after it halts.
//!
//! Request (32 bytes): op, 7 bytes padding, then three little-endian u64s.
//! - `T from to amount`: move `amount` if `from` holds enough;
//! - `Q account`: read a balance;
//! - `Y`: yield to the host forever (round-trip measurement).

#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;

global_asm!(
    ".global _start",
    ".type _start, @function",
    "_start:",
    "mv s0, ra",
    "jal ra, actor_main",
    "mv ra, s0",
    "ret",
);

/// Read a value: a0/a1 key, a2/a3 output buffer. Returns its length, or
/// u64::MAX if absent.
const GET: u64 = 0x200;
/// Write a value: a0/a1 key, a2/a3 value.
const PUT: u64 = 0x201;
/// Return to the host without finishing.
const YIELD: u64 = 0x2ff;

macro_rules! hostcall {
    ($id:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr) => {{
        let result: u64;
        // SAFETY: standard ecalli convention; pointer arguments name live
        // buffers that the host may read or write within their lengths.
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
                lateout("a4") _,
                lateout("a5") _,
                options(nostack),
            );
        }
        result
    }};
}

fn get(account: u64) -> u64 {
    let key = account.to_le_bytes();
    let mut value = [0u8; 8];
    let len = hostcall!(GET, key.as_ptr(), 8, value.as_mut_ptr(), 8);
    if len == 8 {
        u64::from_le_bytes(value)
    } else {
        0
    }
}

fn put(account: u64, balance: u64) {
    let key = account.to_le_bytes();
    let value = balance.to_le_bytes();
    hostcall!(PUT, key.as_ptr(), 8, value.as_ptr(), 8);
}

struct Reply(UnsafeCell<[u64; 3]>);

// SAFETY: a PVM invocation is single-threaded.
unsafe impl Sync for Reply {}

static REPLY: Reply = Reply(UnsafeCell::new([0; 3]));

#[repr(C)]
pub struct Output {
    address: u64,
    len: u64,
}

fn word(request: &[u8], index: usize) -> u64 {
    let start = 8 + index * 8;
    request
        .get(start..start + 8)
        .map_or(0, |bytes| u64::from_le_bytes(bytes.try_into().unwrap()))
}

#[unsafe(no_mangle)]
extern "C" fn actor_main(request: *const u8, len: u64) -> Output {
    // SAFETY: the host maps the request at (a0, a1).
    let request = unsafe { core::slice::from_raw_parts(request, len as usize) };
    let reply = match request.first() {
        Some(b'T') => {
            let (from, to, amount) = (word(request, 0), word(request, 1), word(request, 2));
            let from_balance = get(from);
            let to_balance = get(to);
            if from_balance >= amount && from != to {
                put(from, from_balance - amount);
                put(to, to_balance + amount);
                [1, from_balance - amount, to_balance + amount]
            } else {
                [0, from_balance, to_balance]
            }
        }
        Some(b'Q') => [1, get(word(request, 0)), 0],
        Some(b'Y') => loop {
            hostcall!(YIELD, 0u64, 0u64, 0u64, 0u64);
        },
        _ => [u64::MAX, 0, 0],
    };
    // SAFETY: single-threaded; the host reads the reply after we halt.
    unsafe { *REPLY.0.get() = reply };
    Output {
        address: REPLY.0.get() as u64,
        len: 24,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: `unimp` lowers to a PVM trap.
    unsafe { asm!("unimp", options(noreturn)) }
}
