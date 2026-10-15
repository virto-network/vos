//! What an actor program needs around its handlers and workflows: driving
//! an `async` one and, as macros a program crate invokes, the entry point,
//! the allocator and the panic handler.

use alloc::vec::Vec;
use core::future::Future;
use core::mem::ManuallyDrop;
use core::pin::pin;
use core::task::{Context, Poll, Waker};

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

/// An actor program's heap by default. Every invocation pays for the heap,
/// of whatever kind: the pool prices a machine by its mapped pages, a JAM
/// node's loader maps each, and a workflow, which runs in its actor's
/// program, arms each page it may write at every step
/// (`defaults::ARM_PAGE`). So an actor configures the least heap its
/// largest workflow needs.
pub const PROGRAM_HEAP: usize = 512 << 10;

/// A program's output, by the halt convention: its address in φ7 and its
/// length in φ8. An attestable method's entry returns it, and so do the
/// agent's refine and accumulate.
#[repr(C)]
pub struct Output {
    pub address: u64,
    pub len: u64,
}

impl Output {
    /// `bytes` as the output, leaked: the host reads them once the program
    /// halts.
    pub fn leak(bytes: Vec<u8>) -> Self {
        let bytes = ManuallyDrop::new(bytes);
        Self {
            address: bytes.as_ptr() as u64,
            len: bytes.len() as u64,
        }
    }
}

/// An attestable method's entry: its arguments' address and length, in the
/// standard argument window, and its output.
pub type Entry = unsafe extern "C" fn(*const u8, u64) -> Output;

/// An attestable method of the actor and its entry, which `#[messages]`
/// generates as `__vos_attest_<method>`: the root a kernel is derived from
/// at install, by what the entry reaches.
#[repr(C)]
pub struct Attestable {
    pub method: u64,
    pub entry: Entry,
}

/// An actor program: `actor_program!(crate_name::module)`, naming the
/// module `#[messages]` generates, with a heap of [`PROGRAM_HEAP`] or
/// `heap = N` bytes, its workflows' too. It places the schema first in the
/// program's read-only data, then the table of its attestable methods'
/// entries, `VOS_ATTEST`, and defines the entry point: instruction 0
/// calls the module's `dispatch` with the method in φ7 and returns to the
/// halt address the agent left in φ0. φ8 holds the kind and φ9 the
/// arguments' length, which the agent enforces and `input` reports.
///
/// A workflow starts there too, its method in φ7: its machine runs from its
/// start to its result, pausing at host calls that return only once the
/// agent resumes it, in a later step, restored from its snapshot.
///
/// It belongs in the actor's binary crate alone, once: `VOS_ATTEST`,
/// `_start` and `vos_entry` are unmangled symbols of the program.
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

        #[used]
        #[unsafe(no_mangle)]
        #[unsafe(link_section = ".vos_attest")]
        static VOS_ATTEST: [$crate::runtime::Attestable; $($module)::+::ATTESTABLES.len()] =
            $($module)::+::ATTESTABLES;

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

/// Run a handler or a workflow to completion. Every operation either
/// awaits is ready when polled: the agent completes a nested call before
/// the caller's machine resumes, and a workflow's pause returns only once
/// the agent resumes its machine, in a later step. A future still pending
/// awaited something else, and traps.
pub fn block_on<F: Future>(future: F) -> F::Output {
    let mut context = Context::from_waker(Waker::noop());
    match pin!(future).poll(&mut context) {
        Poll::Ready(output) => output,
        Poll::Pending => panic!("awaited something that is not ready"),
    }
}
