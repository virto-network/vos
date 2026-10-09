//! What an actor program needs around its handlers: driving an `async`
//! handler and, as macros a program crate invokes, the entry point, the
//! allocator and the panic handler.

use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

fn noop_raw() -> RawWaker {
    fn clone(_: *const ()) -> RawWaker {
        noop_raw()
    }
    fn noop(_: *const ()) {}
    static VTABLE: RawWakerVTable = RawWakerVTable::new(clone, noop, noop, noop);
    RawWaker::new(core::ptr::null(), &VTABLE)
}

/// The invocation's arguments, decoded as `T`. Arguments that do not
/// decode trap, which fails the step.
pub fn arguments<T: crate::Decode>() -> T {
    match T::decode(&crate::host::input()) {
        Ok((value, _)) => value,
        Err(_) => panic!("undecodable arguments"),
    }
}

/// A program's global allocator, an [`crate::heap::Heap`] of `$arena`
/// bytes, and its panic handler, a trap. The entry macros include it.
#[macro_export]
macro_rules! program_runtime {
    ($arena:expr) => {
        #[cfg(target_arch = "riscv64")]
        #[global_allocator]
        static VOS_HEAP: $crate::heap::Heap<{ $arena }> = $crate::heap::Heap::new();

        #[cfg(target_arch = "riscv64")]
        #[panic_handler]
        fn vos_panic(_: &::core::panic::PanicInfo<'_>) -> ! {
            // SAFETY: `unimp` lowers to a PVM trap, which fails the step.
            unsafe { ::core::arch::asm!("unimp", options(noreturn)) }
        }

        // These replace compiler_builtins' weak byte loops.
        #[cfg(target_arch = "riscv64")]
        #[unsafe(no_mangle)]
        unsafe extern "C" fn memcmp(a: *const u8, b: *const u8, len: usize) -> i32 {
            // SAFETY: memcmp's contract.
            unsafe { $crate::mem::compare(a, b, len) }
        }

        #[cfg(target_arch = "riscv64")]
        #[unsafe(no_mangle)]
        unsafe extern "C" fn bcmp(a: *const u8, b: *const u8, len: usize) -> i32 {
            // SAFETY: bcmp's contract.
            unsafe { $crate::mem::compare(a, b, len) }
        }
    };
}

/// An actor's or attestable program's heap by default: the pool prices a
/// machine by its mapped pages, so a larger arena costs every call.
pub const PROGRAM_HEAP: usize = 512 << 10;

/// An actor program: `actor_program!(crate_name::module)`, naming the
/// module `#[messages]` generates. It places the schema first in the
/// program's read-only data, and defines the entry point: instruction 0
/// calls the module's `dispatch` with the method in φ7 and returns to the
/// halt address the agent left in φ0. φ8 holds the kind and φ9 the
/// arguments' length, which the agent enforces and `input` reports.
#[macro_export]
macro_rules! actor_program {
    ($($module:ident)::+) => {
        $crate::actor_program!($($module)::+, heap = $crate::runtime::PROGRAM_HEAP);
    };
    ($($module:ident)::+, heap = $heap:expr) => {
        $crate::program_runtime!($heap);

        #[used]
        #[unsafe(link_section = ".vos_schema")]
        static VOS_SCHEMA: [u8; $($module)::+::SCHEMA.len()] = $($module)::+::SCHEMA;

        #[cfg(target_arch = "riscv64")]
        ::core::arch::global_asm!(
            ".global _start",
            ".type _start, @function",
            "_start:",
            "mv s0, ra",
            "jal ra, vos_entry",
            "mv ra, s0",
            "ret",
        );

        #[cfg(target_arch = "riscv64")]
        #[unsafe(no_mangle)]
        extern "C" fn vos_entry(method: u64) {
            $($module)::+::dispatch(method as u32);
        }
    };
}

/// The program of an attestable method: `attestable_program!(path)`, where
/// `path` is the `__vos_attest_<method>` function `#[messages]` generates.
/// The arguments arrive in the standard argument window and the output
/// leaves by the halt convention: its address in φ7 and length in φ8. The
/// program makes no host calls; precompiles aside.
#[macro_export]
macro_rules! attestable_program {
    ($run:path) => {
        $crate::program_runtime!($crate::runtime::PROGRAM_HEAP);

        #[cfg(target_arch = "riscv64")]
        ::core::arch::global_asm!(
            ".global _start",
            ".type _start, @function",
            "_start:",
            "mv s0, ra",
            "jal ra, vos_attest_entry",
            "mv ra, s0",
            "ret",
        );

        #[repr(C)]
        pub struct VosOutput {
            address: u64,
            len: u64,
        }

        #[cfg(target_arch = "riscv64")]
        #[unsafe(no_mangle)]
        extern "C" fn vos_attest_entry(arguments: *const u8, len: u64) -> VosOutput {
            // SAFETY: the loader maps the argument window read-only at
            // (φ7, φ8) for the whole invocation.
            let arguments = unsafe { ::core::slice::from_raw_parts(arguments, len as usize) };
            let output = ::core::mem::ManuallyDrop::new($run(arguments));
            VosOutput {
                address: output.as_ptr() as u64,
                len: output.len() as u64,
            }
        }
    };
}

/// Run a handler to completion. Every operation it awaits is ready when
/// polled: the agent completes a nested call before the caller's machine
/// resumes. A handler that is still pending has awaited something else,
/// which only workflows may do, and traps.
pub fn block_on<F: Future>(future: F) -> F::Output {
    // SAFETY: the vtable's functions ignore the data pointer.
    let waker = unsafe { Waker::from_raw(noop_raw()) };
    let mut context = Context::from_waker(&waker);
    match pin!(future).poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("a handler awaited something that is not ready"),
    }
}
