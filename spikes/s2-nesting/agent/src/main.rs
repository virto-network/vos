//! An agent program hosting the ledger actor as a JAM inner machine.
//!
//! The first argument byte selects the run:
//! - `N warm`: refine. Take inputs until exhausted, run each through the
//!   actor and serve its state calls: reads go to the node (`STATE_GET`)
//!   through an overlay of this refine's own writes; writes are buffered.
//!   `warm` = 1 reuses one actor machine for the whole batch; 0 builds and
//!   expunges one per input. Output: the work result.
//! - `A result`: accumulate a work result through `STATE_PUT`.
//! - `H n`: n empty node host calls.
//! - `Y n`: n actor yields, each a full invoke round trip.
//!
//! Work result: n_writes u32, (key u64, value u64) × n_writes, n_replies
//! u32, reply checksum u64.

#![no_std]
#![no_main]

use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;

global_asm!(
    ".global _start",
    ".type _start, @function",
    "_start:",
    "mv s0, ra",
    "jal ra, agent_main",
    "mv ra, s0",
    "ret",
);

// JAM refine calls for inner machines.
const MACHINE: u64 = 9;
const PEEK: u64 = 10;
const POKE: u64 = 11;
const PAGES: u64 = 12;
const INVOKE: u64 = 13;
const EXPUNGE: u64 = 14;

// Node calls (VOS extensions in this spike).
const INPUT_NEXT: u64 = 0x100;
const STATE_GET: u64 = 0x101;
const STATE_PUT: u64 = 0x102;
const PROGRAM: u64 = 0x103;
const NOP: u64 = 0x104;

// Actor calls served here.
const ACTOR_GET: u64 = 0x200;
const ACTOR_PUT: u64 = 0x201;
const ACTOR_YIELD: u64 = 0x2ff;

const NONE: u64 = u64::MAX;
const ZONE: u64 = 0x1_0000;
const PAGE: u64 = 4096;
const INPUT: u64 = 1 << 24;
const HALT: u64 = (1 << 32) - (1 << 16);
const ACTOR_GAS: u64 = 1_000_000_000;

macro_rules! hostcall {
    ($id:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr) => {{
        let r0: u64;
        let r1: u64;
        // SAFETY: standard ecalli convention; pointer arguments name live
        // buffers of at least the given lengths.
        unsafe {
            asm!(
                "li t0, {id}",
                "csrw 0x801, zero",
                "ecall",
                id = const $id,
                lateout("t0") _,
                inlateout("a0") $a0 as u64 => r0,
                inlateout("a1") $a1 as u64 => r1,
                inlateout("a2") $a2 as u64 => _,
                inlateout("a3") $a3 as u64 => _,
                lateout("a4") _,
                lateout("a5") _,
                options(nostack),
            );
        }
        (r0, r1)
    }};
}

struct Static<T>(UnsafeCell<T>);

// SAFETY: a PVM invocation is single-threaded.
unsafe impl<T> Sync for Static<T> {}

impl<T> Static<T> {
    #[allow(clippy::mut_from_ref)]
    fn get(&self) -> &mut T {
        // SAFETY: single-threaded, and callers never hold two borrows of
        // the same buffer across a call that takes another.
        unsafe { &mut *self.0.get() }
    }
}

const MAX_WRITES: usize = 16_384;
const OVERLAY_SLOTS: usize = 32_768;

static PROGRAM_BUF: Static<[u8; 65_536]> = Static(UnsafeCell::new([0; 65_536]));
static INPUT_BUF: Static<[u8; 4096]> = Static(UnsafeCell::new([0; 4096]));
static FRAME: Static<[u64; 14]> = Static(UnsafeCell::new([0; 14]));
static WRITES: Static<[(u64, u64); MAX_WRITES]> = Static(UnsafeCell::new([(0, 0); MAX_WRITES]));
/// Open-addressing map of this refine's writes: key + 1 (0 = empty), value.
static OVERLAY: Static<[(u64, u64); OVERLAY_SLOTS]> =
    Static(UnsafeCell::new([(0, 0); OVERLAY_SLOTS]));
static OUTPUT: Static<[u8; 16 * MAX_WRITES + 16]> =
    Static(UnsafeCell::new([0; 16 * MAX_WRITES + 16]));

fn le(bytes: &[u8]) -> u64 {
    bytes
        .iter()
        .rev()
        .fold(0, |acc, b| acc << 8 | u64::from(*b))
}

fn page_round(x: u64) -> u64 {
    x.div_ceil(PAGE) * PAGE
}

fn zone_round(x: u64) -> u64 {
    x.div_ceil(ZONE) * ZONE
}

struct Actor {
    id: u64,
    stack_top: u64,
    args_base: u64,
}

/// Build an inner machine from a standard program: code through `machine`,
/// then each region through `pages` and `poke`.
fn load_actor(spi: &[u8]) -> Actor {
    let ro_len = le(&spi[0..3]);
    let rw_len = le(&spi[3..6]);
    let heap_pages = le(&spi[6..8]);
    let stack_len = le(&spi[8..11]);
    let ro = &spi[11..11 + ro_len as usize];
    let rw = &spi[11 + ro_len as usize..11 + (ro_len + rw_len) as usize];
    let at = 11 + (ro_len + rw_len) as usize;
    let code_len = le(&spi[at..at + 4]);
    let code = &spi[at + 4..at + 4 + code_len as usize];

    let (id, _) = hostcall!(MACHINE, code.as_ptr(), code_len, 0u64, 0u64);
    assert!(id < 64);
    let pages = |base: u64, size: u64, mode: u64| {
        let (status, _) = hostcall!(PAGES, id, base / PAGE, size / PAGE, mode);
        assert!(status == 0);
    };
    let poke = |bytes: &[u8], address: u64| {
        if !bytes.is_empty() {
            let (status, _) = hostcall!(POKE, id, bytes.as_ptr(), address, bytes.len());
            assert!(status == 0);
        }
    };

    let ro_size = page_round(ro_len);
    if ro_size > 0 {
        pages(ZONE, ro_size, 2);
        poke(ro, ZONE);
        pages(ZONE, ro_size, 3);
    }
    let rw_base = 2 * ZONE + zone_round(ro_len);
    let rw_size = page_round(rw_len + heap_pages * PAGE);
    if rw_size > 0 {
        pages(rw_base, rw_size, 2);
        poke(rw, rw_base);
    }
    let stack_top = (1 << 32) - 2 * ZONE - INPUT;
    let stack_size = page_round(stack_len);
    pages(stack_top - stack_size, stack_size, 2);
    let args_base = (1 << 32) - ZONE - INPUT;
    pages(args_base, PAGE, 2);
    Actor {
        id,
        stack_top,
        args_base,
    }
}

fn overlay_slot(key: u64) -> usize {
    (key.wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 49) as usize % OVERLAY_SLOTS
}

fn overlay_get(key: u64) -> Option<u64> {
    let table = OVERLAY.get();
    let mut slot = overlay_slot(key);
    loop {
        match table[slot] {
            (0, _) => return None,
            (k, v) if k == key + 1 => return Some(v),
            _ => slot = (slot + 1) % OVERLAY_SLOTS,
        }
    }
}

fn overlay_put(key: u64, value: u64) {
    let table = OVERLAY.get();
    let mut slot = overlay_slot(key);
    loop {
        match table[slot] {
            (0, _) => {
                table[slot] = (key + 1, value);
                return;
            }
            (k, _) if k == key + 1 => {
                table[slot].1 = value;
                return;
            }
            _ => slot = (slot + 1) % OVERLAY_SLOTS,
        }
    }
}

struct Batch {
    writes: usize,
    replies: u32,
    checksum: u64,
}

fn read_inner_u64(actor: &Actor, address: u64) -> u64 {
    let mut bytes = [0u8; 8];
    let (status, _) = hostcall!(PEEK, actor.id, bytes.as_mut_ptr(), address, 8u64);
    assert!(status == 0);
    u64::from_le_bytes(bytes)
}

/// Run one request to completion, serving the actor's calls.
fn call_actor(actor: &Actor, request: &[u8], batch: &mut Batch) {
    let (status, _) = hostcall!(
        POKE,
        actor.id,
        request.as_ptr(),
        actor.args_base,
        request.len()
    );
    assert!(status == 0);
    let frame = FRAME.get();
    *frame = [0; 14];
    frame[0] = ACTOR_GAS;
    frame[1] = HALT;
    frame[2] = actor.stack_top;
    frame[8] = actor.args_base;
    frame[9] = request.len() as u64;
    loop {
        let (status, detail) = hostcall!(INVOKE, actor.id, frame.as_mut_ptr(), 0u64, 0u64);
        // frame[1 + i] is register ω_i.
        match (status, detail) {
            (0, _) => {
                let (address, len) = (frame[8], frame[9]);
                for i in 0..len / 8 {
                    let word = read_inner_u64(actor, address + i * 8);
                    batch.checksum = batch.checksum.rotate_left(7) ^ word;
                }
                batch.replies += 1;
                return;
            }
            (3, ACTOR_GET) => {
                let key = read_inner_u64(actor, frame[8]);
                let value = match overlay_get(key) {
                    Some(value) => value,
                    None => {
                        let mut bytes = [0u8; 8];
                        let key_bytes = key.to_le_bytes();
                        let (len, _) = hostcall!(
                            STATE_GET,
                            key_bytes.as_ptr(),
                            8u64,
                            bytes.as_mut_ptr(),
                            8u64
                        );
                        if len == NONE {
                            0
                        } else {
                            u64::from_le_bytes(bytes)
                        }
                    }
                };
                let bytes = value.to_le_bytes();
                let (status, _) = hostcall!(POKE, actor.id, bytes.as_ptr(), frame[10], 8u64);
                assert!(status == 0);
                frame[8] = 8;
            }
            (3, ACTOR_PUT) => {
                let key = read_inner_u64(actor, frame[8]);
                let value = read_inner_u64(actor, frame[10]);
                overlay_put(key, value);
                WRITES.get()[batch.writes] = (key, value);
                batch.writes += 1;
                frame[8] = 0;
            }
            _ => panic!(),
        }
    }
}

fn refine(warm: bool) -> &'static [u8] {
    let program = PROGRAM_BUF.get();
    let (len, _) = hostcall!(PROGRAM, program.as_mut_ptr(), program.len(), 0u64, 0u64);
    let spi = &program[..len as usize];
    let mut batch = Batch {
        writes: 0,
        replies: 0,
        checksum: 0,
    };
    let mut cached: Option<Actor> = None;
    loop {
        let input = INPUT_BUF.get();
        let (len, _) = hostcall!(INPUT_NEXT, input.as_mut_ptr(), input.len(), 0u64, 0u64);
        if len == NONE {
            break;
        }
        let request = &input[..len as usize];
        if warm {
            let actor = cached.get_or_insert_with(|| load_actor(spi));
            call_actor(actor, request, &mut batch);
        } else {
            let actor = load_actor(spi);
            call_actor(&actor, request, &mut batch);
            hostcall!(EXPUNGE, actor.id, 0u64, 0u64, 0u64);
        }
    }

    let out = OUTPUT.get();
    out[0..4].copy_from_slice(&(batch.writes as u32).to_le_bytes());
    let mut at = 4;
    for (key, value) in &WRITES.get()[..batch.writes] {
        out[at..at + 8].copy_from_slice(&key.to_le_bytes());
        out[at + 8..at + 16].copy_from_slice(&value.to_le_bytes());
        at += 16;
    }
    out[at..at + 4].copy_from_slice(&batch.replies.to_le_bytes());
    out[at + 4..at + 12].copy_from_slice(&batch.checksum.to_le_bytes());
    &out[..at + 12]
}

fn accumulate(result: &[u8]) {
    let writes = le(&result[0..4]) as usize;
    for i in 0..writes {
        let at = 4 + i * 16;
        let (key, value) = (&result[at..at + 8], &result[at + 8..at + 16]);
        hostcall!(STATE_PUT, key.as_ptr(), 8u64, value.as_ptr(), 8u64);
    }
}

fn yields(n: u64) {
    let program = PROGRAM_BUF.get();
    let (len, _) = hostcall!(PROGRAM, program.as_mut_ptr(), program.len(), 0u64, 0u64);
    let actor = load_actor(&program[..len as usize]);
    let request = [b'Y'; 1];
    let (status, _) = hostcall!(POKE, actor.id, request.as_ptr(), actor.args_base, 1u64);
    assert!(status == 0);
    let frame = FRAME.get();
    *frame = [0; 14];
    frame[1] = HALT;
    frame[2] = actor.stack_top;
    frame[8] = actor.args_base;
    frame[9] = 1;
    for _ in 0..n {
        frame[0] = ACTOR_GAS;
        let (status, detail) = hostcall!(INVOKE, actor.id, frame.as_mut_ptr(), 0u64, 0u64);
        assert!(status == 3 && detail == ACTOR_YIELD);
    }
    hostcall!(EXPUNGE, actor.id, 0u64, 0u64, 0u64);
}

#[repr(C)]
pub struct Output {
    address: u64,
    len: u64,
}

#[unsafe(no_mangle)]
extern "C" fn agent_main(arguments: *const u8, len: u64) -> Output {
    // SAFETY: the host maps the argument window read-only at (a0, a1).
    let arguments = unsafe { core::slice::from_raw_parts(arguments, len as usize) };
    let output: &[u8] = match arguments.first() {
        Some(b'N') => refine(arguments.get(1) == Some(&1)),
        Some(b'A') => {
            accumulate(&arguments[1..]);
            &[]
        }
        Some(b'H') => {
            for _ in 0..le(&arguments[1..9]) {
                hostcall!(NOP, 0u64, 0u64, 0u64, 0u64);
            }
            &[]
        }
        Some(b'Y') => {
            yields(le(&arguments[1..9]));
            &[]
        }
        _ => &[],
    };
    Output {
        address: output.as_ptr() as u64,
        len: output.len() as u64,
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: `unimp` lowers to a PVM trap.
    unsafe { asm!("unimp", options(noreturn)) }
}
