//! What an actor program needs around its handlers and workflows: driving
//! an `async` one and, as macros a program crate invokes, the entry point,
//! the allocator and the panic handler.

use alloc::vec::Vec;
use core::future::Future;

use core::mem::ManuallyDrop;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use vos_wire::result::KernelReturn;
use vos_wire::served::{Served, representative_row, space_root};
use vos_wire::vos_anchor::{RootKind, RootRead};

/// The invocation's arguments, decoded as `T`. Arguments that do not
/// decode trap, which fails the step.
pub fn arguments<T: crate::Decode>() -> T {
    match T::decode(&crate::host::input()) {
        Ok((value, _)) => value,
        Err(_) => panic!("undecodable arguments"),
    }
}

/// A program's global allocator, an [`crate::heap::Heap`] over an arena
/// of `$arena` bytes in its own section, `.vos_heap`, which the guest's
/// linker script places last in the read-write data; and its panic
/// handler, a trap. The entry macros include it. With `actor`, an actor
/// program's: a handler or a kernel is given the arena's first
/// [`vos_wire::abi::INVOCATION_HEAP`] bytes alone.
#[macro_export]
macro_rules! program_runtime {
    (@heap $arena:expr, $actor:literal) => {
        #[cfg(target_arch = "riscv64")]
        #[unsafe(link_section = ".vos_heap")]
        static VOS_ARENA: $crate::heap::Arena<{ $arena }> = $crate::heap::Arena::new();

        #[cfg(target_arch = "riscv64")]
        #[global_allocator]
        static VOS_HEAP: $crate::heap::Heap<{ $arena }, $actor> =
            $crate::heap::Heap::new(&VOS_ARENA);

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
    ($arena:expr) => {
        $crate::program_runtime!(@heap $arena, false);
    };
    ($arena:expr, actor) => {
        $crate::program_runtime!(@heap $arena, true);
    };
}

/// An actor program's heap by default, [`vos_wire::abi::INVOCATION_HEAP`].
/// An install derives programs that hold at most its first 512 KiB, all a
/// handler or a kernel maps; a workflow, which runs in its actor's program,
/// maps the rest past it, and arms each page it may write at every step
/// (`defaults::ARM_PAGE`). So an actor configures the least heap its
/// largest workflow needs, and its handlers run within the first 512 KiB of
/// it: past them, an allocation fails and the invocation traps.
pub const PROGRAM_HEAP: usize = vos_wire::abi::INVOCATION_HEAP;

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

/// An attestable method's entry: its arguments' address and length, which
/// its kernel's prologue read through the witness input, and where its
/// io-hash goes, which the prologue leaves in φ9..φ12 at the halt; and its
/// output.
pub type Entry = unsafe extern "C" fn(*const u8, u64, *mut [u8; 32]) -> Output;

/// The end of an attestable method of no public argument that reads no
/// root: its encoded `output`, leaked for the host, and its io-hash
/// ([`vos_pvm_precompiles::compute_io_hash`]) written at `io_hash`, over
/// empty public arguments and no root.
///
/// # Safety
///
/// `io_hash` must point at 32 writable bytes.
pub unsafe fn attested_output(output: Vec<u8>, io_hash: *mut [u8; 32]) -> Output {
    let hash = vos_pvm_precompiles::compute_io_hash(&[], &output, &[]);
    // SAFETY: the caller's contract.
    unsafe { io_hash.write(hash) };
    Output::leak(output)
}

/// An attestable method's end: its statement's parts, `public_args`, its
/// encoded `output` and the `roots` it read, encoded as a
/// [`KernelReturn`] and leaked for the host, and their io-hash written at
/// `io_hash`.
///
/// # Safety
///
/// `io_hash` must point at 32 writable bytes.
pub unsafe fn attested(
    public_args: Vec<u8>,
    output: Vec<u8>,
    roots: Vec<RootRead>,
    io_hash: *mut [u8; 32],
) -> Output {
    let parts = KernelReturn {
        public_args,
        output,
        roots,
    };
    // SAFETY: the caller's contract.
    unsafe { io_hash.write(parts.io_hash()) };
    Output::leak(crate::Encode::encode(&parts))
}

/// The rows a read at a window's cut is served, decoded from the whole of
/// `input`, the witness input past the arguments: kept for the rest of the
/// kernel's run, which its view's maps answer from. Bytes that are not one
/// [`Served`] trap.
pub fn served(input: &[u8]) -> &'static Served {
    let served = match <Served as crate::Decode>::decode(input) {
        Ok((served, used)) if used == input.len() => served,
        _ => panic!("undecodable served rows"),
    };
    alloc::boxed::Box::leak(alloc::boxed::Box::new(served))
}

/// The prologue of a kernel that reads at a window's cut: `served`'s rows,
/// each of its instance's committed rows and strictly increasing by key,
/// checked against the agent's root by one multiproof; the agent's root
/// against the representative's root by its space path, its leaf's value
/// committed with `rep_salt`; and the space root `S_w` over the
/// representative's root, the root read it states. A refusal traps, which
/// fails the attest.
pub fn verify_served(served: &Served) -> RootRead {
    let prefix = vos_wire::keys::instance_committed(served.instance);
    let mut claims: Vec<(&[u8], Option<vos_tree::Hash>)> = Vec::with_capacity(served.rows.len());
    for (index, (key, read)) in served.rows.iter().enumerate() {
        assert!(key.starts_with(&prefix), "a row of another instance");
        assert!(
            index == 0 || served.rows[index - 1].0 < *key,
            "rows out of order"
        );
        let commitment = read
            .as_ref()
            .map(|(salt, value)| vos_tree::value_hash(&vos_tree::Blake2b, salt, value));
        claims.push((key.as_slice(), commitment));
    }
    vos_tree::verify_encoded(
        &vos_tree::Blake2b,
        &served.rows_proof,
        &served.agent_root,
        &claims,
    )
    .expect("the rows' proof");
    let row = representative_row(served.agent, RootKind::Space, served.window);
    let commitment = vos_tree::value_hash(&vos_tree::Blake2b, &served.rep_salt, &served.agent_root);
    vos_tree::verify_encoded(
        &vos_tree::Blake2b,
        &served.space_path,
        &served.rep_root,
        &[(row.as_slice(), Some(commitment))],
    )
    .expect("the space path");
    RootRead {
        kind: RootKind::Space,
        space: served.space,
        window: served.window,
        root: space_root(&served.space, served.window, &served.rep_root),
    }
}

/// An attestable method of the actor and its entry, which `#[messages]`
/// generates as `__vos_attest_<method>`: the root a kernel is derived from
/// at install, by what the entry reaches. The method's id is the word's low
/// 32 bits; [`READS_SERVED`] marks a `&self` method.
#[repr(C)]
pub struct Attestable {
    pub method: u64,
    pub entry: Entry,
}

/// The bit of an [`Attestable`]'s method word that marks a `&self` method:
/// its kernel reads, after its arguments, the rows served at a window's
/// cut, which an install's derivation gives room for.
pub const READS_SERVED: u64 = 1 << 32;

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
        $crate::program_runtime!($heap, actor);

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
