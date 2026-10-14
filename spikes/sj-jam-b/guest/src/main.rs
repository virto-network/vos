//! Probe service for Gray Paper 0.8.0 behaviours slice 4 relies on.
//!
//! Refine reads its payload as a list of one-letter commands:
//! - `F`: fault tracking of written pages in an inner machine, `expunge`'s
//!   counter at a host-call exit, and a restore from that counter;
//! - `A`: the gas of arming a 2,048-page region read-only in one call;
//! - `X`: export two 4 KiB pages as segments;
//! - `I`: fetch both imports and check their bytes;
//! - `U`: the gas of a host call the host does not serve, and of `log`;
//! - `P`: the protocol's gas parameters (`fetch` kind 0).
//!
//! Its output is the payload, then one fixed-size record per measured call.
//! Accumulate stores each input under `r:<payload>` and under `last`.

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
    "jal ra, probe_refine",
    "mv ra, s0",
    "ret",
    ".global accumulate",
    ".type accumulate, @function",
    "accumulate:",
    "mv s0, ra",
    "jal ra, probe_accumulate",
    "mv ra, s0",
    "ret",
);

const GAS: u64 = 0;
const FETCH: u64 = 2;
const WRITE: u64 = 5;
const EXPORT: u64 = 8;
const MACHINE: u64 = 9;
const PEEK: u64 = 10;
const POKE: u64 = 11;
const PAGES: u64 = 12;
const INVOKE: u64 = 13;
const EXPUNGE: u64 = 14;
const LOG: u64 = 100;
/// A VOS extension (`instantiate`), which a JAM node does not serve.
const UNSERVED: u64 = 0x480;

const NONE: u64 = u64::MAX;

/// `fetch` kinds.
const FETCH_PARAMETERS: u64 = 0;
const FETCH_ANY_IMPORT: u64 = 5;
const FETCH_OUR_IMPORT: u64 = 6;
const FETCH_INPUT: u64 = 15;

/// `pages` modes.
const ALLOC_RW: u64 = 2;
const SET_RO: u64 = 3;
const SET_RW: u64 = 4;

const PAGE: usize = 4096;
/// W_G: a segment's size.
const SEGMENT: usize = 4104;

/// The inner program, as a compact code blob (no jump table, entry width 1,
/// 37 bytes of code, then the opcode bitmask). One basic block:
///
/// ```text
///  0: store_imm_u32 [0x10000], 0xaabbccdd   page 16
///  9: store_imm_u32 [0x11008], 0x11223344   page 17
/// 18: ecalli 7
/// 20: store_imm_u32 [0x10004], 0x55667788   page 16 again
/// 29: load_imm r0, 0xffff0000
/// 35: jump_ind r0, 0                        halt
/// ```
static INNER: [u8; 45] = [
    0x00, 0x01, 37, //
    32, 3, 0x00, 0x00, 0x01, 0xdd, 0xcc, 0xbb, 0xaa, //
    32, 3, 0x08, 0x10, 0x01, 0x44, 0x33, 0x22, 0x11, //
    10, 7, //
    32, 3, 0x04, 0x00, 0x01, 0x88, 0x77, 0x66, 0x55, //
    51, 0x00, 0x00, 0x00, 0xff, 0xff, //
    50, 0x00, //
    0x01, 0x02, 0x14, 0x20, 0x08,
];
/// The counter just after the inner program's `ecalli`.
const AFTER_HOST_CALL: u64 = 20;
const INNER_GAS: u64 = 1_000_000;
/// The arena whose arming is measured: 2,048 pages (8 MiB) from page 32.
const ARENA_FIRST: u64 = 32;
const ARENA_PAGES: u64 = 2048;

/// Record steps. The tool names them.
mod step {
    pub const CALIBRATE: u8 = 1;
    pub const MACHINE: u8 = 2;
    pub const ALLOC_RW: u8 = 3;
    pub const SET_RO: u8 = 4;
    pub const INVOKE: u8 = 5;
    pub const SET_RW: u8 = 6;
    pub const PEEK: u8 = 7;
    pub const EXPUNGE: u8 = 8;
    pub const POKE: u8 = 9;
    pub const CHECK: u8 = 10;
    pub const ARENA_ALLOC_RW: u8 = 11;
    pub const ARENA_SET_RO: u8 = 12;
    pub const ARENA_SET_RW: u8 = 13;
    pub const EXPORT: u8 = 14;
    pub const FETCH_OUR: u8 = 15;
    pub const FETCH_ANY: u8 = 16;
    pub const UNSERVED: u8 = 17;
    pub const LOG: u8 = 18;
    pub const START: u8 = 19;
    pub const PARAMETERS: u8 = 20;
    pub const POKE_READ_ONLY: u8 = 21;
    pub const SEGMENT: u8 = 22;
    pub const DONE: u8 = 0xff;
}

/// Call host function `id` with φ7..φ12 set, between two `gas` calls, in
/// one straight-line block: the block's instructions were charged on entry,
/// so the difference between the two readings is this call's charge plus
/// one `gas` call. Returns (φ7, φ8, difference).
macro_rules! timed {
    ($id:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr, $a5:expr) => {{
        let r7: u64;
        let r8: u64;
        let before: u64;
        let after: u64;
        // SAFETY: the standard ecalli convention passes arguments in
        // a0..a5 and returns in a0 (and a1 for `invoke`). Pointer
        // arguments name live guest buffers the host may write.
        unsafe {
            asm!(
                "li t0, 0",
                "csrw 0x801, zero",
                "ecall",
                "mv t2, a0",
                "mv a0, t1",
                "li t0, {id}",
                "csrw 0x801, zero",
                "ecall",
                "mv t1, a0",
                "li t0, 0",
                "csrw 0x801, zero",
                "ecall",
                id = const $id,
                inout("t1") $a0 as u64 => r7,
                out("t2") before,
                out("a0") after,
                inout("a1") $a1 as u64 => r8,
                inlateout("a2") $a2 as u64 => _,
                inlateout("a3") $a3 as u64 => _,
                inlateout("a4") $a4 as u64 => _,
                inlateout("a5") $a5 as u64 => _,
                out("t0") _,
                options(nostack),
            );
        }
        (r7, r8, before.wrapping_sub(after))
    }};
}

macro_rules! hostcall {
    ($id:expr, $a0:expr, $a1:expr, $a2:expr, $a3:expr, $a4:expr) => {{
        let result: u64;
        // SAFETY: as in `timed!`.
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
    let target = b"vos-probe";
    hostcall!(
        LOG,
        2u64,
        target.as_ptr(),
        target.len(),
        message.as_ptr(),
        message.len()
    );
}

#[repr(C)]
pub struct Output {
    address: u64,
    len: u64,
}

struct Buffers {
    frame: [u8; 112],
    page16: [u8; PAGE],
    page17: [u8; PAGE],
    segment: [u8; SEGMENT],
    input: [u8; 8192],
}

static mut OUT: [u8; 8192] = [0; 8192];

static mut BUFFERS: Buffers = Buffers {
    frame: [0; 112],
    page16: [0; PAGE],
    page17: [0; PAGE],
    segment: [0; SEGMENT],
    input: [0; 8192],
};

fn buffers() -> &'static mut Buffers {
    // SAFETY: a PVM invocation is single-threaded and each entry takes the
    // buffers exactly once.
    unsafe { &mut *core::ptr::addr_of_mut!(BUFFERS) }
}

/// The output under construction: the payload, then 33-byte records of a
/// step, φ7, φ8, the gas difference and an extra value.
struct Records<'a> {
    out: &'a mut [u8],
    len: usize,
}

impl Records<'_> {
    fn push(&mut self, step: u8, r7: u64, r8: u64, gas: u64, extra: u64) {
        if self.len + 33 > self.out.len() {
            return;
        }
        self.out[self.len] = step;
        for (index, value) in [r7, r8, gas, extra].into_iter().enumerate() {
            let at = self.len + 1 + index * 8;
            self.out[at..at + 8].copy_from_slice(&value.to_le_bytes());
        }
        self.len += 33;
    }
}

/// Gray Paper natural decoding (appendix C).
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

fn frame_gas(frame: &[u8; 112]) -> u64 {
    u64::from_le_bytes(frame[..8].try_into().unwrap())
}

fn set_frame_gas(frame: &mut [u8; 112], gas: u64) {
    frame[..8].copy_from_slice(&gas.to_le_bytes());
}

/// `invoke` with a fresh gas allowance; records the exit (φ7), its detail
/// (φ8), the outer gas difference and the inner gas used.
fn invoke(records: &mut Records, machine: u64, frame: &mut [u8; 112]) -> (u64, u64) {
    set_frame_gas(frame, INNER_GAS);
    let (exit, detail, gas) = timed!(INVOKE, machine, frame.as_mut_ptr(), 0, 0, 0, 0);
    let used = INNER_GAS.wrapping_sub(frame_gas(frame));
    records.push(step::INVOKE, exit, detail, gas, used);
    (exit, detail)
}

fn pages(records: &mut Records, step: u8, machine: u64, first: u64, count: u64, mode: u64) {
    let (result, _, gas) = timed!(PAGES, machine, first, count, mode, 0, 0);
    records.push(step, result, first, gas, count);
}

/// Behaviours 1 and 2: faults on read-only pages, their repair, `expunge`
/// at a host-call exit, and a restore at that counter.
fn probe_faults(records: &mut Records, buffers: &mut Buffers) {
    let frame = &mut buffers.frame;
    let (machine, _, gas) = timed!(MACHINE, INNER.as_ptr(), INNER.len(), 0, 0, 0, 0);
    records.push(step::MACHINE, machine, 0, gas, 0);
    pages(records, step::ALLOC_RW, machine, 16, 2, ALLOC_RW);
    pages(records, step::SET_RO, machine, 16, 2, SET_RO);
    // Page 16 faults, then page 17, then the host call exits.
    invoke(records, machine, frame);
    pages(records, step::SET_RW, machine, 16, 1, SET_RW);
    invoke(records, machine, frame);
    pages(records, step::SET_RW, machine, 17, 1, SET_RW);
    invoke(records, machine, frame);
    // The snapshot: both pages, then the counter.
    let (result, _, gas) = timed!(
        PEEK,
        machine,
        buffers.page16.as_mut_ptr(),
        0x10000,
        PAGE,
        0,
        0
    );
    records.push(step::PEEK, result, 0x10000, gas, PAGE as u64);
    let (result, _, gas) = timed!(
        PEEK,
        machine,
        buffers.page17.as_mut_ptr(),
        0x11000,
        PAGE,
        0,
        0
    );
    records.push(step::PEEK, result, 0x11000, gas, PAGE as u64);
    let (counter, _, gas) = timed!(EXPUNGE, machine, 0, 0, 0, 0, 0);
    records.push(step::EXPUNGE, counter, 0, gas, AFTER_HOST_CALL);

    // The restore: the counter, the pages written into a fresh machine and
    // armed read-only, the registers from the frame.
    let (machine, _, gas) = timed!(MACHINE, INNER.as_ptr(), INNER.len(), counter, 0, 0, 0);
    records.push(step::MACHINE, machine, counter, gas, 0);
    pages(records, step::ALLOC_RW, machine, 16, 2, ALLOC_RW);
    let (result, _, gas) = timed!(POKE, machine, buffers.page16.as_ptr(), 0x10000, PAGE, 0, 0);
    records.push(step::POKE, result, 0x10000, gas, PAGE as u64);
    let (result, _, gas) = timed!(POKE, machine, buffers.page17.as_ptr(), 0x11000, PAGE, 0, 0);
    records.push(step::POKE, result, 0x11000, gas, PAGE as u64);
    pages(records, step::SET_RO, machine, 16, 2, SET_RO);
    // `poke` needs a writable page: this one is refused and writes nothing.
    let zero = [0u8; 4];
    let (result, _, gas) = timed!(POKE, machine, zero.as_ptr(), 0x10000, 4, 0, 0);
    records.push(step::POKE_READ_ONLY, result, 0x10000, gas, 4);
    // Page 16 faults at counter 20, then the program halts.
    invoke(records, machine, frame);
    pages(records, step::SET_RW, machine, 16, 1, SET_RW);
    invoke(records, machine, frame);
    let mut check = [0u8; 12];
    let first = hostcall!(PEEK, machine, check.as_mut_ptr(), 0x10000, 8, 0);
    let second = hostcall!(PEEK, machine, check[8..].as_mut_ptr(), 0x11008, 4, 0);
    let expected = [
        0xdd, 0xcc, 0xbb, 0xaa, 0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11,
    ];
    let words = (
        u64::from_le_bytes(check[..8].try_into().unwrap()),
        u64::from(u32::from_le_bytes(check[8..].try_into().unwrap())),
    );
    records.push(
        step::CHECK,
        words.0,
        words.1,
        first | second,
        u64::from(check == expected),
    );
    let (counter, _, gas) = timed!(EXPUNGE, machine, 0, 0, 0, 0, 0);
    records.push(step::EXPUNGE, counter, 0, gas, 0);
}

/// Arming a large region: allocate 2,048 writable pages, set them read-only
/// in one call, then read-write again.
fn probe_arena(records: &mut Records) {
    let (machine, _, gas) = timed!(MACHINE, INNER.as_ptr(), INNER.len(), 0, 0, 0, 0);
    records.push(step::MACHINE, machine, 0, gas, 0);
    pages(
        records,
        step::ARENA_ALLOC_RW,
        machine,
        ARENA_FIRST,
        ARENA_PAGES,
        ALLOC_RW,
    );
    pages(
        records,
        step::ARENA_SET_RO,
        machine,
        ARENA_FIRST,
        ARENA_PAGES,
        SET_RO,
    );
    pages(
        records,
        step::ARENA_SET_RW,
        machine,
        ARENA_FIRST,
        ARENA_PAGES,
        SET_RW,
    );
    let (counter, _, gas) = timed!(EXPUNGE, machine, 0, 0, 0, 0, 0);
    records.push(step::EXPUNGE, counter, 0, gas, 0);
}

/// The bytes of exported page `index`: a tag, then a pattern.
fn segment_byte(index: u8, at: usize) -> u8 {
    match at {
        0 => b'S',
        1 => b'E',
        2 => b'G',
        3 => b'0' + index,
        _ => (at as u8).wrapping_mul(31).wrapping_add(7) ^ (index.wrapping_mul(0x5a)),
    }
}

/// FNV-1a over a byte range, to compare segments across hosts.
fn fnv(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    hash
}

/// Behaviour 3, package 1: export two 4 KiB pages.
fn probe_export(records: &mut Records, buffers: &mut Buffers) {
    for index in 0..2u8 {
        let page = &mut buffers.page16;
        for (at, byte) in page.iter_mut().enumerate() {
            *byte = segment_byte(index, at);
        }
        let (result, _, gas) = timed!(EXPORT, page.as_ptr(), PAGE, 0, 0, 0, 0);
        records.push(step::EXPORT, result, u64::from(index), gas, fnv(page));
    }
}

/// Behaviour 3, package 2: fetch both imports and check them against the
/// exported pattern, zero-padded to a segment.
fn probe_import(records: &mut Records, buffers: &mut Buffers) {
    for index in 0..3u64 {
        let segment = &mut buffers.segment;
        segment.fill(0xee);
        let (length, _, gas) = timed!(
            FETCH,
            segment.as_mut_ptr(),
            0,
            SEGMENT,
            FETCH_OUR_IMPORT,
            index,
            0
        );
        let matches = length == SEGMENT as u64
            && segment[..PAGE]
                .iter()
                .enumerate()
                .all(|(at, byte)| *byte == segment_byte(index as u8, at))
            && segment[PAGE..].iter().all(|byte| *byte == 0);
        let first = u64::from_le_bytes(segment[..8].try_into().unwrap());
        records.push(step::FETCH_OUR, length, first, gas, u64::from(matches));
        if length == SEGMENT as u64 {
            records.push(step::SEGMENT, fnv(&segment[..PAGE]), index, 0, 0);
        }
    }
    // The same second import, named by work item and index.
    let segment = &mut buffers.segment;
    let (length, _, gas) = timed!(
        FETCH,
        segment.as_mut_ptr(),
        0,
        SEGMENT,
        FETCH_ANY_IMPORT,
        0,
        1
    );
    let first = u64::from_le_bytes(segment[..8].try_into().unwrap());
    records.push(step::FETCH_ANY, length, first, gas, fnv(&segment[..PAGE]));
}

/// Refine arguments: `E(c, i, s, ↕payload, H(p))`.
#[unsafe(no_mangle)]
extern "C" fn probe_refine(arguments: *const u8, len: u64) -> Output {
    // SAFETY: the host maps the argument window read-only at (a0, a1).
    let arguments = unsafe { core::slice::from_raw_parts(arguments, len as usize) };
    log(b"refine");
    let payload = decode_natural(arguments)
        .and_then(|(_, rest)| decode_natural(rest))
        .and_then(|(_, rest)| decode_natural(rest))
        .and_then(|(_, rest)| decode_natural(rest))
        .and_then(|(length, rest)| rest.get(..length as usize))
        .unwrap_or(b"?");
    let buffers = buffers();
    // SAFETY: as for `buffers`.
    let out = unsafe { &mut *core::ptr::addr_of_mut!(OUT) };
    let tag = payload.len().min(32);
    out[0] = tag as u8;
    out[1..1 + tag].copy_from_slice(&payload[..tag]);
    let mut records = Records {
        out,
        len: 1 + tag,
    };
    let start = hostcall!(GAS, 0, 0, 0, 0, 0);
    records.push(step::START, start, 0, 0, 0);
    let (_, _, gas) = timed!(GAS, 0, 0, 0, 0, 0, 0);
    records.push(step::CALIBRATE, 0, 0, gas, 0);
    for command in payload {
        match command {
            b'F' => probe_faults(&mut records, buffers),
            b'A' => probe_arena(&mut records),
            b'X' => probe_export(&mut records, buffers),
            b'I' => probe_import(&mut records, buffers),
            b'P' => {
                let input = &mut buffers.input;
                let length = hostcall!(
                    FETCH,
                    input.as_mut_ptr(),
                    0,
                    input.len(),
                    FETCH_PARAMETERS,
                    0
                );
                let word = |at: usize| u64::from_le_bytes(input[at..at + 8].try_into().unwrap());
                // E8(B_I), E8(B_L), E8(B_S), E2(C), E4(D), E4(E), then
                // E8(G_A), E8(G_I), E8(G_R), E8(G_T).
                records.push(step::PARAMETERS, word(34), word(42), length, 0);
                records.push(step::PARAMETERS, word(50), word(58), length, 1);
            }
            b'U' => {
                let (result, _, gas) = timed!(UNSERVED, 0, 0, 0, 0, 0, 0);
                records.push(step::UNSERVED, result, 0, gas, 0);
                let target = b"vos-probe";
                let message = b"timed";
                let (result, _, gas) = timed!(
                    LOG,
                    2,
                    target.as_ptr(),
                    target.len(),
                    message.as_ptr(),
                    message.len(),
                    0
                );
                records.push(step::LOG, result, 0, gas, 0);
            }
            _ => {}
        }
    }
    records.push(step::DONE, 0, 0, 0, 0);
    log(b"refined");
    Output {
        address: records.out.as_ptr() as u64,
        len: records.len as u64,
    }
}

/// The refine output inside an operand input, `0 ‖ E(p, e, a, y, g,
/// O(result), ↕trace)`, when the result is Ok.
fn operand_output(input: &[u8]) -> Option<&[u8]> {
    let (&kind, rest) = input.split_first()?;
    if kind != 0 {
        return None;
    }
    let (_, rest) = decode_natural(rest.get(128..)?)?;
    let (&result, rest) = rest.split_first()?;
    if result != 0 {
        return None;
    }
    let (length, rest) = decode_natural(rest)?;
    rest.get(..length as usize)
}

/// Accumulate arguments: `E(t, s, |inputs|)`.
#[unsafe(no_mangle)]
extern "C" fn probe_accumulate(arguments: *const u8, len: u64) -> Output {
    // SAFETY: the host maps the argument window read-only at (a0, a1).
    let arguments = unsafe { core::slice::from_raw_parts(arguments, len as usize) };
    log(b"accumulate");
    let count = decode_natural(arguments)
        .and_then(|(_, rest)| decode_natural(rest))
        .and_then(|(_, rest)| decode_natural(rest))
        .map_or(1, |(count, _)| count);
    let input = &mut buffers().input;
    for index in 0..count {
        let length = hostcall!(FETCH, input.as_mut_ptr(), 0u64, input.len(), FETCH_INPUT, index);
        if length == NONE {
            log(b"no input");
            continue;
        }
        let stored = (length as usize).min(input.len());
        let value = &input[..stored];
        let mut key = [0u8; 34];
        key[..2].copy_from_slice(b"r:");
        let key_len = match operand_output(value) {
            Some(output) if !output.is_empty() => {
                let tag = usize::from(output[0]).min(32).min(output.len() - 1);
                key[2..2 + tag].copy_from_slice(&output[1..1 + tag]);
                2 + tag
            }
            _ => {
                key[..3].copy_from_slice(b"err");
                3
            }
        };
        for key in [&key[..key_len], b"last".as_slice()] {
            let previous = hostcall!(WRITE, key.as_ptr(), key.len(), value.as_ptr(), stored, 0u64);
            if previous == u64::MAX - 4 {
                log(b"write refused: insufficient balance");
            }
        }
        log(b"stored input");
    }
    Output { address: 0, len: 0 }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: `unimp` lowers to a PVM trap.
    unsafe { asm!("unimp", options(noreturn)) }
}
