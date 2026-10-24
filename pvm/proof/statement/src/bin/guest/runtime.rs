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
/// 2^16, 256 MiB). Only the pages the allocator reaches are touched; the
/// high-water mark says how much of it an invocation needs.
const ARENA_BYTES: usize = 64 << 20;

#[repr(C, align(4096))]
pub struct Stack(UnsafeCell<[u8; STACK_BYTES]>);
// SAFETY: a PVM invocation is single-threaded.
unsafe impl Sync for Stack {}

#[unsafe(no_mangle)]
pub static VERIFY_STACK: Stack = Stack(UnsafeCell::new([0; STACK_BYTES]));

// ── The allocator: a bump over the arena ─────────────────────────────────
//
// An invocation verifies one proof, or applies one block's operands, and
// ends: what it frees is reclaimed only when it is the arena's last block,
// so an allocation is a few instructions, which on the PVM's per-block gas
// is most of what a decode costs.

#[repr(C, align(4096))]
struct Arena([u8; ARENA_BYTES]);

pub struct State {
    /// Bump offset into the arena: the high-water mark.
    pub top: usize,
    live: usize,
    pub peak_live: usize,
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
        live: 0,
        peak_live: 0,
        allocs: 0,
    }),
};

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the allocator's: its sums are of `Layout` sizes (at most `isize::MAX`) and \
              arena offsets below `ARENA_BYTES`, and a free never exceeds what is live"
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

    /// Whether the block of `bytes` at `ptr` is the arena's last.
    fn is_last(&self, ptr: *mut u8, bytes: usize) -> bool {
        ptr as usize + bytes == self.base() + self.state().top
    }

    fn account(&self, grow: usize, shrink: usize) {
        let state = self.state();
        state.live = state.live + grow - shrink;
        state.peak_live = state.peak_live.max(state.live);
    }
}

#[allow(
    clippy::arithmetic_side_effects,
    reason = "the allocator's: its sums are of `Layout` sizes (at most `isize::MAX`) and \
              arena offsets below `ARENA_BYTES`, and a free never exceeds what is live"
)]
unsafe impl GlobalAlloc for Heap {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let state = self.state();
        state.allocs += 1;
        let base = self.base();
        let start = (base + state.top).next_multiple_of(layout.align()) - base;
        let end = start + layout.size();
        if end > ARENA_BYTES {
            return core::ptr::null_mut();
        }
        state.top = end;
        self.account(layout.size(), 0);
        (base + start) as *mut u8
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        self.account(0, layout.size());
        if self.is_last(ptr, layout.size()) {
            self.state().top -= layout.size();
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let state = self.state();
        if self.is_last(ptr, layout.size()) && state.top - layout.size() + new_size <= ARENA_BYTES {
            state.top = state.top - layout.size() + new_size;
            self.account(new_size, layout.size());
            return ptr;
        }
        // SAFETY: as GlobalAlloc::realloc's default.
        unsafe {
            let new = self.alloc(Layout::from_size_align_unchecked(new_size, layout.align()));
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
