//! The venue's JAM programs' runtime, shared by the guests that link the
//! final verifier (`final-verify`, `final-verify-test` and
//! `vos-statement-service`'s): a stack of its own and the entries onto it,
//! the heap, the host calls and their convention, the output, the panic
//! handler and the single-core atomic libcalls.

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

/// The program's entries, each a label (`_start` first, at instruction 0)
/// whose code moves the stack to [`VERIFY_STACK`] and calls its
/// `extern "C"` main, returning with the main's φ7 and φ8. `STACK_BYTES`
/// in scope where it is used.
macro_rules! entries {
    ($($label:literal => $main:literal),+ $(,)?) => {
        core::arch::global_asm!(
            $(
                concat!(".global ", $label),
                concat!(".type ", $label, ", @function"),
                concat!($label, ":"),
                "mv s0, ra",
                "lla t0, VERIFY_STACK",
                "li t1, {size}",
                "add sp, t0, t1",
                concat!("jal ra, ", $main),
                "mv ra, s0",
                "ret",
            )+
            size = const STACK_BYTES,
        );
    };
}

/// What an entry's main returns: the address and the length of its
/// output (φ7, φ8).
#[repr(C)]
pub struct Output {
    pub address: u64,
    pub len: u64,
}

// ── The allocator ────────────────────────────────────────────────────────

#[path = "heap.rs"]
mod heap;

pub use heap::Heap;

#[global_allocator]
pub static HEAP: Heap<ARENA_BYTES> = Heap::new();

// ── Host calls ───────────────────────────────────────────────────────────

/// The host calls the guests make, by their Gray Paper index.
#[allow(dead_code, reason = "each guest makes some of them")]
#[derive(Clone, Copy)]
#[repr(u64)]
pub enum Call {
    Gas = 0,
    Fetch = 2,
    Read = 4,
    Write = 5,
    HistoricalLookup = 7,
}

/// `fetch`'s kinds (φ10) the guests read.
#[allow(dead_code, reason = "each guest reads some of them")]
#[derive(Clone, Copy)]
#[repr(u64)]
pub enum FetchKind {
    /// The running item's extrinsic φ11.
    OurExtrinsic = 4,
    /// Work item φ11's payload.
    Payload = 13,
    /// Accumulate's input φ11.
    Input = 15,
}

/// A host call's answer of none: no such value, or nothing written.
pub const NONE: u64 = u64::MAX;

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
                id = const $id as u64,
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
    hostcall!(Call::Gas, [0; 6])
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
