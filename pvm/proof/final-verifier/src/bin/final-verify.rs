//! The final verifier as a JAM refine program (`--features pvm-guest`,
//! built by `just check-no-std` for the PVM target): it verifies a wrap
//! proof the way a JAM service would, and reports its gas by phase.
//!
//! Input, as a JAM work item gives it:
//! - work item 0's payload (`fetch`, kind 13), [`PAYLOAD_LEN`] bytes: the
//!   24 public words (each a little-endian `u32`), the proof's Blake2b-256
//!   hash and its length (`u32`, little-endian);
//! - the proof, postcard, as a preimage of the running service, read by
//!   `historical_lookup`.
//!
//! Output (φ7 address, φ8 length): [`Report`], every field a little-endian
//! `u64`: the verdict, the gas left at each phase, the heap's figures and a
//! refusal's text. Blake2b-256 is computed in software: JAM serves no
//! hash.

#![no_std]
#![no_main]

extern crate alloc;

use alloc::vec::Vec;
use core::alloc::{GlobalAlloc, Layout};
use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;
use core::fmt::Write;

use vos_final_verifier::{PUBLIC_WORDS, WrapProof};

/// The verifier's own stack, in `.bss`: the standard program's stack is
/// the read-only zone's offset, 64 KiB. Its pages written say how much
/// the verify needs.
const STACK_BYTES: usize = 1 << 20;
/// The heap arena, in `.bss` (a standard program's zero pages are at most
/// 2^16, 256 MiB). Only the pages the allocator reaches are
/// touched; the high-water mark says how much of it the verify needs.
const ARENA_BYTES: usize = 64 << 20;

#[repr(C, align(4096))]
pub struct Stack(UnsafeCell<[u8; STACK_BYTES]>);
// SAFETY: a PVM invocation is single-threaded.
unsafe impl Sync for Stack {}

#[unsafe(no_mangle)]
pub static VERIFY_STACK: Stack = Stack(UnsafeCell::new([0; STACK_BYTES]));

global_asm!(
    ".global _start",
    ".type _start, @function",
    "_start:",
    "mv s0, ra",
    "lla t0, VERIFY_STACK",
    "li t1, {size}",
    "add sp, t0, t1",
    "jal ra, verify_main",
    "mv ra, s0",
    "ret",
    size = const STACK_BYTES,
);

// ── The allocator: power-of-two classes to 64 KiB, page runs above ──────

const MIN_SHIFT: u32 = 4;
const MAX_SMALL_SHIFT: u32 = 16;
const CLASSES: usize = (MAX_SMALL_SHIFT - MIN_SHIFT + 1) as usize;
const LARGE_SLOTS: usize = 512;
const PAGE: usize = 4096;

#[repr(C, align(4096))]
struct Arena([u8; ARENA_BYTES]);

struct State {
    /// Bump offset into the arena: the high-water mark.
    top: usize,
    /// Free-list heads per class (0: empty); a free block's first word
    /// links the next.
    free: [usize; CLASSES],
    /// Free page runs (address, bytes; address 0: an empty slot).
    large: [(usize, usize); LARGE_SLOTS],
    live: usize,
    peak_live: usize,
    total: usize,
    allocs: usize,
}

struct Heap {
    arena: UnsafeCell<Arena>,
    state: UnsafeCell<State>,
}

// SAFETY: a PVM invocation is single-threaded.
unsafe impl Sync for Heap {}

#[global_allocator]
static HEAP: Heap = Heap {
    arena: UnsafeCell::new(Arena([0; ARENA_BYTES])),
    state: UnsafeCell::new(State {
        top: 0,
        free: [0; CLASSES],
        large: [(0, 0); LARGE_SLOTS],
        live: 0,
        peak_live: 0,
        total: 0,
        allocs: 0,
    }),
};

/// A request's class (`Some`, its block 2^class bytes) or a page run.
fn class_of(layout: &Layout) -> Option<u32> {
    let need = layout.size().max(layout.align()).max(1 << MIN_SHIFT);
    let shift = usize::BITS - (need - 1).leading_zeros();
    (shift <= MAX_SMALL_SHIFT && layout.align() <= PAGE).then_some(shift)
}

fn round_page(n: usize) -> usize {
    n.div_ceil(PAGE) * PAGE
}

impl Heap {
    fn base(&self) -> usize {
        self.arena.get() as usize
    }

    #[allow(clippy::mut_from_ref)]
    fn state(&self) -> &mut State {
        // SAFETY: single-threaded, and no borrow outlives a call.
        unsafe { &mut *self.state.get() }
    }

    fn bump(&self, bytes: usize, align: usize) -> *mut u8 {
        let state = self.state();
        let start = (self.base() + state.top).next_multiple_of(align) - self.base();
        let end = start + bytes;
        if end > ARENA_BYTES {
            return core::ptr::null_mut();
        }
        state.top = end;
        (self.base() + start) as *mut u8
    }

    fn free_run(&self, address: usize, bytes: usize) {
        let state = self.state();
        if address + bytes == self.base() + state.top {
            state.top -= bytes;
            return;
        }
        if let Some(slot) = state.large.iter_mut().find(|slot| slot.0 == 0) {
            *slot = (address, bytes);
        }
    }

    fn account(&self, grow: usize, shrink: usize) {
        let state = self.state();
        state.live = state.live + grow - shrink;
        state.peak_live = state.peak_live.max(state.live);
        state.total += grow;
    }
}

unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let state = self.state();
        state.allocs += 1;
        let ptr = match class_of(&layout) {
            Some(shift) => {
                let slot = &mut state.free[(shift - MIN_SHIFT) as usize];
                if *slot != 0 {
                    let block = *slot;
                    // SAFETY: a free block's first word is the next link.
                    *slot = unsafe { *(block as *const usize) };
                    block as *mut u8
                } else {
                    let bytes = 1usize << shift;
                    self.bump(bytes, bytes.min(PAGE))
                }
            }
            None => {
                let bytes = round_page(layout.size());
                let align = layout.align().max(PAGE);
                let fit = state
                    .large
                    .iter_mut()
                    .filter(|slot| slot.0 != 0 && slot.1 >= bytes && slot.0.is_multiple_of(align))
                    .min_by_key(|slot| slot.1);
                match fit {
                    Some(slot) => {
                        let (address, run) = *slot;
                        *slot = if run > bytes {
                            (address + bytes, run - bytes)
                        } else {
                            (0, 0)
                        };
                        address as *mut u8
                    }
                    None => self.bump(bytes, align),
                }
            }
        };
        if !ptr.is_null() {
            self.account(layout.size(), 0);
        }
        ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.account(0, layout.size());
        match class_of(&layout) {
            Some(shift) => {
                let slot = &mut self.state().free[(shift - MIN_SHIFT) as usize];
                // SAFETY: the block is at least 16 bytes and 8-aligned.
                unsafe { *(ptr as *mut usize) = *slot };
                *slot = ptr as usize;
            }
            None => self.free_run(ptr as usize, round_page(layout.size())),
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // SAFETY: GlobalAlloc's contract: `layout.align()` is a power of two.
        let new_layout = unsafe { Layout::from_size_align_unchecked(new_size, layout.align()) };
        match (class_of(&layout), class_of(&new_layout)) {
            (Some(old), Some(new)) if old == new => {
                self.account(new_size, layout.size());
                return ptr;
            }
            (None, None) => {
                let old_run = round_page(layout.size());
                let new_run = round_page(new_size);
                let address = ptr as usize;
                let state = self.state();
                if new_run <= old_run {
                    if new_run < old_run {
                        self.free_run(address + new_run, old_run - new_run);
                    }
                    self.account(new_size, layout.size());
                    return ptr;
                }
                if address + old_run == self.base() + state.top
                    && state.top + (new_run - old_run) <= ARENA_BYTES
                {
                    state.top += new_run - old_run;
                    self.account(new_size, layout.size());
                    return ptr;
                }
            }
            _ => {}
        }
        // SAFETY: as GlobalAlloc::realloc's default.
        unsafe {
            let new = self.alloc(new_layout);
            if !new.is_null() {
                core::ptr::copy_nonoverlapping(ptr, new, layout.size().min(new_size));
                self.dealloc(ptr, layout);
            }
            new
        }
    }
}

// ── Host calls ───────────────────────────────────────────────────────────

const GAS: u64 = 0;
const FETCH: u64 = 2;
const HISTORICAL_LOOKUP: u64 = 7;
const FETCH_PAYLOAD: u64 = 13;
const NONE: u64 = u64::MAX;

/// `ecalli id` with φ7..φ12 = `a`; φ7 after it.
macro_rules! hostcall {
    ($id:expr, $a:expr) => {{
        let a: [u64; 6] = $a;
        let r: u64;
        // SAFETY: the standard ecalli convention; pointer arguments name
        // live buffers of at least the given lengths.
        unsafe {
            asm!(
                "li t0, {id}",
                "csrw 0x801, zero",
                "ecall",
                id = const $id,
                lateout("t0") _,
                inlateout("a0") a[0] => r,
                inlateout("a1") a[1] => _,
                inlateout("a2") a[2] => _,
                inlateout("a3") a[3] => _,
                inlateout("a4") a[4] => _,
                inlateout("a5") a[5] => _,
                options(nostack),
            );
        }
        r
    }};
}

fn gas_left() -> u64 {
    hostcall!(GAS, [0; 6])
}

// ── The verify ──────────────────────────────────────────────────────────

/// The payload: the public words, the proof's hash and its length.
pub const PAYLOAD_LEN: usize = 4 * PUBLIC_WORDS + 32 + 4;

/// Verdicts.
const ACCEPT: u64 = 1;
const REJECT: u64 = 0;
const BAD_PAYLOAD: u64 = 2;
const NO_PREIMAGE: u64 = 3;
const UNDECODABLE: u64 = 4;

struct Static<T>(UnsafeCell<T>);
// SAFETY: a PVM invocation is single-threaded.
unsafe impl<T> Sync for Static<T> {}

static PAYLOAD: Static<[u8; 256]> = Static(UnsafeCell::new([0; 256]));
static REPORT: Static<Report> = Static(UnsafeCell::new(Report::new()));
static PANIC: Static<[u8; 512]> = Static(UnsafeCell::new([0; 512]));

/// What the program returns.
#[repr(C)]
pub struct Report {
    verdict: u64,
    gas_start: u64,
    gas_after_lookup: u64,
    gas_after_decode: u64,
    gas_end: u64,
    proof_len: u64,
    peak_live: u64,
    high_water: u64,
    allocs: u64,
    error_len: u64,
    error: [u8; 192],
}

impl Report {
    const fn new() -> Self {
        Self {
            verdict: u64::MAX,
            gas_start: 0,
            gas_after_lookup: 0,
            gas_after_decode: 0,
            gas_end: 0,
            proof_len: 0,
            peak_live: 0,
            high_water: 0,
            allocs: 0,
            error_len: 0,
            error: [0; 192],
        }
    }
}

/// A `fmt::Write` into a fixed buffer, truncating.
struct Cursor<'a> {
    buf: &'a mut [u8],
    len: usize,
}

impl Write for Cursor<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let take = s.len().min(self.buf.len() - self.len);
        self.buf[self.len..self.len + take].copy_from_slice(&s.as_bytes()[..take]);
        self.len += take;
        Ok(())
    }
}

#[repr(C)]
pub struct Output {
    address: u64,
    len: u64,
}

#[unsafe(no_mangle)]
extern "C" fn verify_main() -> Output {
    // SAFETY: single-threaded; the host reads the report after halt.
    let report = unsafe { &mut *REPORT.0.get() };
    report.gas_start = gas_left();
    report.verdict = verify(report);
    report.gas_end = gas_left();
    let state = HEAP.state();
    report.peak_live = state.peak_live as u64;
    report.high_water = state.top as u64;
    report.allocs = state.allocs as u64;
    Output {
        address: report as *mut Report as u64,
        len: core::mem::size_of::<Report>() as u64,
    }
}

fn verify(report: &mut Report) -> u64 {
    // SAFETY: single-threaded; nothing else borrows the payload buffer.
    let payload = unsafe { &mut *PAYLOAD.0.get() };
    let len = hostcall!(
        FETCH,
        [
            payload.as_mut_ptr() as u64,
            0,
            payload.len() as u64,
            FETCH_PAYLOAD,
            0,
            0
        ]
    );
    if len != PAYLOAD_LEN as u64 {
        return BAD_PAYLOAD;
    }
    let words: [u32; PUBLIC_WORDS] =
        core::array::from_fn(|i| u32::from_le_bytes(payload[4 * i..4 * i + 4].try_into().unwrap()));
    let at = 4 * PUBLIC_WORDS;
    let hash: [u8; 32] = payload[at..at + 32].try_into().unwrap();
    let proof_len = u32::from_le_bytes(payload[at + 32..at + 36].try_into().unwrap()) as usize;
    report.proof_len = proof_len as u64;

    let mut bytes: Vec<u8> = Vec::with_capacity(proof_len);
    let found = hostcall!(
        HISTORICAL_LOOKUP,
        [
            NONE,
            hash.as_ptr() as u64,
            bytes.as_mut_ptr() as u64,
            0,
            proof_len as u64,
            0
        ]
    );
    if found != proof_len as u64 {
        return NO_PREIMAGE;
    }
    // SAFETY: the host wrote all `proof_len` bytes.
    unsafe { bytes.set_len(proof_len) };
    report.gas_after_lookup = gas_left();

    let Ok(proof) = postcard::from_bytes::<WrapProof>(&bytes) else {
        return UNDECODABLE;
    };
    drop(bytes);
    report.gas_after_decode = gas_left();

    match vos_final_verifier::verify(proof, &words) {
        Ok(_) => ACCEPT,
        Err(error) => {
            let mut cursor = Cursor {
                buf: &mut report.error,
                len: 0,
            };
            let _ = write!(cursor, "{error}");
            report.error_len = cursor.len as u64;
            REJECT
        }
    }
}

/// A panic traps with φ7 = 0xDEAD and φ8, φ9 the message's address and
/// length.
#[panic_handler]
fn panic(info: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: single-threaded; the panic ends the run.
    let buf = unsafe { &mut *PANIC.0.get() };
    let mut cursor = Cursor { buf, len: 0 };
    let _ = write!(cursor, "{info}");
    let (address, len) = (cursor.buf.as_ptr() as u64, cursor.len as u64);
    // SAFETY: `unimp` lowers to a PVM trap.
    unsafe {
        asm!(
            "unimp",
            in("a0") 0xDEADu64,
            in("a1") address,
            in("a2") len,
            options(noreturn)
        )
    }
}

// ── Single-core atomic libcalls ──────────────────────────────────────────
//
// The PVM is RV64EM with no `a` extension. foldhash's global seed and
// tracing-core's callsites (both in stwo's verify graph) need
// `core::sync::atomic`, which a `max-atomic-width: 0` target lacks; this
// build's target says 64 without `+a`, so LLVM lowers atomics to these
// libcalls. A PVM invocation is single-threaded: each is its plain
// counterpart.
mod atomic_shim {
    macro_rules! shims {
        ($t:ty, $load:ident, $store:ident, $exchange:ident, $cas:ident) => {
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $load(ptr: *const $t, _order: i32) -> $t {
                unsafe { core::ptr::read(ptr) }
            }
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $store(ptr: *mut $t, value: $t, _order: i32) {
                unsafe { core::ptr::write(ptr, value) }
            }
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $exchange(ptr: *mut $t, value: $t, _order: i32) -> $t {
                unsafe { core::ptr::replace(ptr, value) }
            }
            #[unsafe(no_mangle)]
            pub unsafe extern "C" fn $cas(
                ptr: *mut $t,
                expected: *mut $t,
                desired: $t,
                _success: i32,
                _failure: i32,
            ) -> bool {
                unsafe {
                    let current = core::ptr::read(ptr);
                    if current == *expected {
                        core::ptr::write(ptr, desired);
                        true
                    } else {
                        *expected = current;
                        false
                    }
                }
            }
        };
    }
    shims!(
        u8,
        __atomic_load_1,
        __atomic_store_1,
        __atomic_exchange_1,
        __atomic_compare_exchange_1
    );
    shims!(
        u16,
        __atomic_load_2,
        __atomic_store_2,
        __atomic_exchange_2,
        __atomic_compare_exchange_2
    );
    shims!(
        u32,
        __atomic_load_4,
        __atomic_store_4,
        __atomic_exchange_4,
        __atomic_compare_exchange_4
    );
    shims!(
        u64,
        __atomic_load_8,
        __atomic_store_8,
        __atomic_exchange_8,
        __atomic_compare_exchange_8
    );

    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __atomic_fetch_add_8(ptr: *mut u64, value: u64, _order: i32) -> u64 {
        unsafe {
            let old = core::ptr::read(ptr);
            core::ptr::write(ptr, old.wrapping_add(value));
            old
        }
    }
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn __atomic_fetch_sub_8(ptr: *mut u64, value: u64, _order: i32) -> u64 {
        unsafe {
            let old = core::ptr::read(ptr);
            core::ptr::write(ptr, old.wrapping_sub(value));
            old
        }
    }
}
