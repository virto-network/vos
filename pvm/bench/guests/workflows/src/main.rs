//! Three representative workflows for measuring snapshot cost.
//!
//! The first argument byte selects the workflow:
//! - `T`: a transfer that awaits one remote risk check, then calls the
//!   ledger synchronously;
//! - `S`: a five-step saga, each step awaiting a remote reply;
//! - `C`: a long computation over a 2 MiB vector that checkpoints sixteen
//!   times.
//!
//! The output window is a short text result so a harness can compare an
//! uninterrupted run with one restored from snapshots at every suspension.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::collections::BTreeMap;
use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;

global_asm!(
    ".global _start",
    ".type _start, @function",
    "_start:",
    "mv s0, ra",
    "jal ra, s1_main",
    "mv ra, s0",
    "ret",
);

/// Await a reply from another agent: a0/a1 message, a2/a3 reply buffer.
/// Returns the reply length. The workflow suspends here.
const AWAIT_AGENT: u64 = 0x200;
/// Synchronous call into an instance of the same agent; same arguments.
const CALL_LOCAL: u64 = 0x201;
/// End the current step without awaiting anything.
const CHECKPOINT: u64 = 0x202;

const ARENA_BYTES: usize = 8 * 1024 * 1024;

#[repr(C, align(16))]
struct Arena {
    bytes: UnsafeCell<[u8; ARENA_BYTES]>,
    next: UnsafeCell<usize>,
}

// SAFETY: a PVM invocation is single-threaded.
unsafe impl Sync for Arena {}

unsafe impl GlobalAlloc for Arena {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        // SAFETY: single-threaded; the bump pointer only grows within the
        // arena and every allocation receives a disjoint range.
        unsafe {
            let next = &mut *self.next.get();
            let aligned = (*next + layout.align() - 1) & !(layout.align() - 1);
            let end = aligned + layout.size();
            if end > ARENA_BYTES {
                return core::ptr::null_mut();
            }
            *next = end;
            (self.bytes.get() as *mut u8).add(aligned)
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[global_allocator]
static ARENA: Arena = Arena {
    bytes: UnsafeCell::new([0; ARENA_BYTES]),
    next: UnsafeCell::new(0),
};

macro_rules! hostcall {
    ($id:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr) => {{
        let result: u64;
        // SAFETY: standard ecalli convention; pointer arguments name live
        // guest buffers that the host may write.
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
                options(nostack),
            );
        }
        result
    }};
}

fn call(id_await: bool, message: &[u8]) -> Vec<u8> {
    let mut reply = vec![0u8; 512];
    let len = if id_await {
        hostcall!(
            AWAIT_AGENT,
            message.as_ptr(),
            message.len(),
            reply.as_mut_ptr(),
            reply.len()
        )
    } else {
        hostcall!(
            CALL_LOCAL,
            message.as_ptr(),
            message.len(),
            reply.as_mut_ptr(),
            reply.len()
        )
    };
    reply.truncate((len as usize).min(512));
    reply
}

fn checkpoint() {
    hostcall!(CHECKPOINT, 0u64, 0u64, 0u64, 0u64);
}

struct TransferRequest {
    from: String,
    to: String,
    amount: u64,
    memo: String,
    tags: Vec<String>,
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

fn transfer(input: &[u8]) -> String {
    let fields: Vec<&[u8]> = input.split(|b| *b == b'|').collect();
    let request = TransferRequest {
        from: text(fields.first().copied().unwrap_or(b"")),
        to: text(fields.get(1).copied().unwrap_or(b"")),
        amount: text(fields.get(2).copied().unwrap_or(b"0")).parse().unwrap_or(0),
        memo: text(fields.get(3).copied().unwrap_or(b"")),
        tags: fields.iter().skip(4).map(|f| text(f)).collect(),
    };
    let check = format!(
        "risk.check from={} to={} amount={} memo={} tags={}",
        request.from,
        request.to,
        request.amount,
        request.memo,
        request.tags.join(",")
    );
    let verdict = text(&call(true, check.as_bytes()));
    if !verdict.starts_with("ok") {
        return format!("rejected:{verdict}");
    }
    let order = format!(
        "ledger.transfer {}->{} {} [{}]",
        request.from, request.to, request.amount, verdict
    );
    let receipt = text(&call(false, order.as_bytes()));
    format!("done:{receipt}")
}

fn saga(input: &[u8]) -> String {
    let mut results: BTreeMap<u32, Vec<u8>> = BTreeMap::new();
    let mut summary = String::new();
    for step in 0..5u32 {
        let mut message = Vec::with_capacity(256);
        message.extend_from_slice(format!("saga.step {step} ").as_bytes());
        message.extend_from_slice(input);
        for (key, value) in &results {
            message.extend_from_slice(format!(" {key}:{}", value.len()).as_bytes());
        }
        let reply = call(true, &message);
        summary.push_str(&format!("{step}={} ", reply.len()));
        results.insert(step, reply);
    }
    let total: usize = results.values().map(Vec::len).sum();
    format!("saga:{summary}total={total}")
}

fn compute(_input: &[u8]) -> String {
    const N: usize = 262_144;
    const ROUNDS: usize = 16;
    let mut data = vec![0u64; N];
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    for value in data.iter_mut() {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *value = state;
    }
    checkpoint();
    let chunk = N / ROUNDS;
    for round in 0..ROUNDS {
        data[round * chunk..(round + 1) * chunk].sort_unstable();
        checkpoint();
    }
    let mut digest = 0u64;
    for (index, value) in data.iter().enumerate().step_by(997) {
        digest = digest.rotate_left(5) ^ value ^ index as u64;
    }
    format!("compute:{digest:016x}")
}

#[repr(C)]
pub struct Output {
    address: u64,
    len: u64,
}

#[unsafe(no_mangle)]
extern "C" fn s1_main(arguments: *const u8, len: u64) -> Output {
    // SAFETY: the host maps the argument window read-only at (a0, a1).
    let arguments = unsafe { core::slice::from_raw_parts(arguments, len as usize) };
    let (selector, input) = arguments.split_first().unwrap_or((&b'?', &[]));
    let result = match selector {
        b'T' => transfer(input),
        b'S' => saga(input),
        b'C' => compute(input),
        _ => String::from("unknown"),
    };
    let bytes = result.into_bytes().leak();
    Output {
        address: bytes.as_ptr() as u64,
        len: bytes.len() as u64,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: `unimp` lowers to a PVM trap.
    unsafe { asm!("unimp", options(noreturn)) }
}
