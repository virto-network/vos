//! The venue's JAM programs' runtime, shared by the guests that link the
//! final verifier (`final-verify`, `final-verify-test` and
//! `vos-statement-service`'s): a stack of its own, the heap, the host-call
//! convention, the panic handler and the single-core atomic libcalls.

use core::alloc::{GlobalAlloc, Layout};
use core::cell::UnsafeCell;
use core::fmt::Write;

/// The verifier's own stack, in `.bss`: the standard program's stack is
/// the read-only zone's offset, 64 KiB. Its pages written say how much
/// the verify needs.
pub const STACK_BYTES: usize = 1 << 20;
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

// ── The allocator: power-of-two classes to 64 KiB, page runs above ──────

const MIN_SHIFT: u32 = 4;
const MAX_SMALL_SHIFT: u32 = 16;
const CLASSES: usize = (MAX_SMALL_SHIFT - MIN_SHIFT + 1) as usize;
const LARGE_SLOTS: usize = 512;
const PAGE: usize = 4096;

#[repr(C, align(4096))]
struct Arena([u8; ARENA_BYTES]);

pub struct State {
    /// Bump offset into the arena: the high-water mark.
    pub top: usize,
    /// Free-list heads per class (0: empty); a free block's first word
    /// links the next.
    free: [usize; CLASSES],
    /// Free page runs (address, bytes; address 0: an empty slot).
    large: [(usize, usize); LARGE_SLOTS],
    live: usize,
    pub peak_live: usize,
    total: usize,
    pub allocs: usize,
}

pub struct Heap {
    arena: UnsafeCell<Arena>,
    state: UnsafeCell<State>,
}

// SAFETY: a PVM invocation is single-threaded.
unsafe impl Sync for Heap {}

#[global_allocator]
pub static HEAP: Heap = Heap {
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
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "the allocator's: its sums are of `Layout` sizes (at most `isize::MAX`, a page \
              run's within it) and arena offsets below `ARENA_BYTES`, its index a class \
              `class_of` bounds by `MAX_SMALL_SHIFT`, and a free never exceeds what is live"
)]
fn class_of(layout: &Layout) -> Option<u32> {
    let need = layout.size().max(layout.align()).max(1 << MIN_SHIFT);
    let shift = usize::BITS - (need - 1).leading_zeros();
    (shift <= MAX_SMALL_SHIFT && layout.align() <= PAGE).then_some(shift)
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "the allocator's: its sums are of `Layout` sizes (at most `isize::MAX`, a page \
              run's within it) and arena offsets below `ARENA_BYTES`, its index a class \
              `class_of` bounds by `MAX_SMALL_SHIFT`, and a free never exceeds what is live"
)]
fn round_page(n: usize) -> usize {
    n.div_ceil(PAGE) * PAGE
}

#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "the allocator's: its sums are of `Layout` sizes (at most `isize::MAX`, a page \
              run's within it) and arena offsets below `ARENA_BYTES`, its index a class \
              `class_of` bounds by `MAX_SMALL_SHIFT`, and a free never exceeds what is live"
)]
impl Heap {
    fn base(&self) -> usize {
        self.arena.get() as usize
    }

    #[allow(clippy::mut_from_ref)]
    pub fn state(&self) -> &mut State {
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

#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    reason = "the allocator's: its sums are of `Layout` sizes (at most `isize::MAX`, a page \
              run's within it) and arena offsets below `ARENA_BYTES`, its index a class \
              `class_of` bounds by `MAX_SMALL_SHIFT`, and a free never exceeds what is live"
)]
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

/// `ecalli id` with φ7..φ12 = `a`; φ7 after it.
macro_rules! hostcall {
    ($id:expr, $a:expr) => {{
        let a: [u64; 6] = $a;
        let r: u64;
        // SAFETY: the standard ecalli convention; pointer arguments name
        // live buffers of at least the given lengths.
        unsafe {
            core::arch::asm!(
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

/// The gas left (`gas`, host call 0).
pub fn gas_left() -> u64 {
    hostcall!(0, [0; 6])
}

/// A static a single-threaded invocation borrows mutably.
pub struct Static<T>(pub UnsafeCell<T>);
// SAFETY: a PVM invocation is single-threaded.
unsafe impl<T> Sync for Static<T> {}

/// A `fmt::Write` into a fixed buffer, truncating.
pub struct Cursor<'a> {
    pub buf: &'a mut [u8],
    pub len: usize,
}

impl Write for Cursor<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let free = self.buf.get_mut(self.len..).unwrap_or_default();
        let take = s.len().min(free.len());
        for (to, &from) in free.iter_mut().zip(s.as_bytes()) {
            *to = from;
        }
        self.len = self.len.saturating_add(take);
        Ok(())
    }
}

static PANIC: Static<[u8; 512]> = Static(UnsafeCell::new([0; 512]));

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
        core::arch::asm!(
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
