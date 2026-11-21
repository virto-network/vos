//! SIGSEGV-based memory bounds checking for the recompiler.
//!
//! Memory accesses in JIT code skip
//! software bounds checks. Instead, guard pages (PROT_NONE) beyond heap_top
//! trigger SIGSEGV, which this handler intercepts and redirects to the
//! existing exit sequence via ucontext modification (no longjmp).
//!
//! A fault is the guest's only when its instruction is exactly a guest
//! access's (a trap-table entry) and its address lies in the guest window,
//! `[base, base + 2^32)`. Any other fault in compiled code is a backend
//! failure: the handler restores the stack pointer the entry recorded and
//! returns through the epilogue alone, with no guest-visible exit, and the
//! machine is never run again.
//!
//! A write to a guest-writable page of a slot that does not track writes
//! yet is not a guest fault: the handler starts tracking the slot and
//! returns, so the store retries (`Activation`).
//!
//! It assumes it stays the process's SIGSEGV handler once installed (no
//! later `sigaction` replaces it while compiled code runs), and that any
//! handler installed before it is one it may chain to for a fault outside
//! compiled code.

use std::cell::{Cell, RefCell};
use std::ptr::null_mut;
use std::sync::OnceLock;

use super::JitContext;
use super::codegen::{EXIT_PAGE_FAULT, EXIT_TRACKING_FAILED};
use super::memory::{Activated, Activation};

/// Per-thread state accessible from the signal handler. It lives on the
/// host's stack, away from every mapping native code addresses.
#[repr(C)]
pub struct SignalState {
    /// Start of native code region (absolute address).
    pub code_start: usize,
    /// End of native code region (exclusive).
    pub code_end: usize,
    /// Absolute address of exit_label in native code.
    pub exit_label_addr: usize,
    /// Absolute address of the epilogue alone, where a backend failure
    /// returns.
    pub abort_label_addr: usize,
    /// The guest window's base: guest address 0.
    pub window_base: usize,
    /// Pointer to JitContext (for writing exit_reason/exit_arg/pc).
    pub ctx_ptr: *mut JitContext,
    /// Trap table: sorted by native_offset. (native_offset, pvm_pc).
    /// Points into the CompiledCode's trap_table (lives as long as the `Arc<CodeCap>`).
    pub trap_table_ptr: *const (u32, u32),
    pub trap_table_len: usize,
    /// Dense PVM-PC → native retry offset table. Entries are `-1` when no
    /// fault retry is valid at that byte position.
    pub fault_resume_offsets_ptr: *const i32,
    pub fault_resume_offsets_len: usize,
    /// Write-tracking activation for the guest window, or null when the
    /// window does not track writes.
    pub(crate) activation: *const Activation,
    /// The stack pointer after the entry's prologue, which native code
    /// writes here (its second argument) as it starts.
    pub entry_rsp: u64,
    /// Set by the handler when native code faulted outside a guest access.
    pub backend_fault: Cell<bool>,
}

impl SignalState {
    /// Whether the handler aborted the last run as a backend failure.
    pub fn backend_faulted(&self) -> bool {
        self.backend_fault.get()
    }
}

// SAFETY: SignalState is only accessed by the owning thread (set before JIT call,
// read by signal handler on same thread, cleared after JIT call).
unsafe impl Send for SignalState {}

thread_local! {
    pub static SIGNAL_STATE: Cell<*mut SignalState> = const { Cell::new(null_mut()) };
}

static INSTALLED: OnceLock<Result<(), String>> = OnceLock::new();

thread_local! {
    /// This thread's alternate signal stack, once installed: the handler
    /// runs on it, and it is unmapped when the thread exits.
    static ALTERNATE_STACK: RefCell<Option<AlternateStack>> = const { RefCell::new(None) };
}

// SAFETY: sigaction is a POD struct — zero-initialized is a valid (SIG_DFL) state.
// Written once inside INSTALLED's initialization, read by the signal handler
// only after it.
static mut PREV_SIGSEGV: libc::sigaction = unsafe { std::mem::zeroed() };

/// Ensure the SIGSEGV handler is installed (once per process) and this
/// thread has an alternate signal stack (once per thread). An error when
/// either cannot be: native code must not run then.
pub fn ensure_installed() -> Result<(), String> {
    ALTERNATE_STACK.with(|stack| {
        let mut stack = stack.borrow_mut();
        if stack.is_none() {
            *stack = Some(AlternateStack::install()?);
        }
        Ok::<_, String>(())
    })?;
    // SAFETY: sigaction is a process-wide OS API; the OnceLock runs it
    // exactly once across all threads.
    INSTALLED
        .get_or_init(|| unsafe { install_handler() })
        .clone()
}

/// # Safety
///
/// Replaces the process's SIGSEGV disposition: called once (`INSTALLED`),
/// and before any other thread reads `PREV_SIGSEGV`.
unsafe fn install_handler() -> Result<(), String> {
    // SAFETY: sigaction() is called with a properly initialized sigaction struct.
    // The handler pointer is a valid extern "C" fn with the correct signature.
    // PREV_SIGSEGV is written once here and only read afterward.
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_flags = libc::SA_SIGINFO | libc::SA_ONSTACK;
        sa.sa_sigaction = sigsegv_handler as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        if libc::sigaction(libc::SIGSEGV, &sa, &raw mut PREV_SIGSEGV) != 0 {
            return Err(format!(
                "sigaction(SIGSEGV): {}",
                std::io::Error::last_os_error()
            ));
        }
    }
    Ok(())
}

/// The smallest alternate stack the handler runs on.
const MIN_STACK: usize = 64 * 4096;

/// An alternate signal stack this module mapped for its thread, or none
/// when the thread already had an adequate one of its own.
struct AlternateStack {
    /// The mapping, a guard page below the stack, and its length.
    mapping: Option<(*mut libc::c_void, usize)>,
}

impl AlternateStack {
    /// Give the calling thread an alternate signal stack, unless it has an
    /// adequate one.
    fn install() -> Result<Self, String> {
        let error = |what: &str| format!("{what}: {}", std::io::Error::last_os_error());
        // SAFETY: sigaltstack reads and writes valid stack_t structs and
        // configures only the calling thread; the mapping is fresh, and
        // unmapped on every failure.
        unsafe {
            let mut old: libc::stack_t = std::mem::zeroed();
            if libc::sigaltstack(std::ptr::null(), &mut old) != 0 {
                return Err(error("sigaltstack"));
            }
            if old.ss_flags & libc::SS_DISABLE == 0 && old.ss_size >= MIN_STACK {
                return Ok(Self { mapping: None });
            }
            let page_size: usize = 4096;
            let len = page_size + MIN_STACK; // guard page + stack
            let ptr = libc::mmap(
                null_mut(),
                len,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS,
                -1,
                0,
            );
            if ptr == libc::MAP_FAILED {
                return Err(error("mapping an alternate signal stack"));
            }
            // The stack above its guard page.
            let stack = ptr.cast::<u8>().add(page_size).cast::<libc::c_void>();
            let new_stack = libc::stack_t {
                ss_sp: stack,
                ss_flags: 0,
                ss_size: MIN_STACK,
            };
            if libc::mprotect(stack, MIN_STACK, libc::PROT_READ | libc::PROT_WRITE) != 0
                || libc::sigaltstack(&new_stack, null_mut()) != 0
            {
                let failure = error("installing an alternate signal stack");
                libc::munmap(ptr, len);
                return Err(failure);
            }
            Ok(Self {
                mapping: Some((ptr, len)),
            })
        }
    }
}

impl Drop for AlternateStack {
    fn drop(&mut self) {
        if let Some((ptr, len)) = self.mapping {
            let disable = libc::stack_t {
                ss_sp: null_mut(),
                ss_flags: libc::SS_DISABLE,
                ss_size: 0,
            };
            // SAFETY: the thread is exiting, so no handler runs on the
            // stack; once disabled, the mapping is this owner's alone.
            unsafe {
                if libc::sigaltstack(&disable, null_mut()) == 0 {
                    libc::munmap(ptr, len);
                }
            }
        }
    }
}

/// SIGSEGV handler: intercepts page faults from JIT code and redirects to the
/// exit sequence. Only handles faults at registered trap sites within our
/// native code region; all others are delegated to the previous handler.
///
/// # Safety
///
/// Called by the kernel alone, with the `siginfo` and `ucontext` of a
/// SIGSEGV on this thread.
unsafe extern "C" fn sigsegv_handler(
    signum: libc::c_int,
    _siginfo: *mut libc::siginfo_t,
    ucontext: *mut libc::c_void,
) {
    // SAFETY: Called by the OS signal mechanism with valid siginfo/ucontext pointers.
    // SIGNAL_STATE is thread-local and set by the calling thread before JIT entry.
    // state_ptr is only non-null during JIT execution on this thread.
    // The ucontext cast is valid on x86-64 Linux (ucontext_t layout).
    // ctx_ptr points to a live JitContext owned by the same thread's call stack.
    // Modifying REG_RIP redirects execution to exit_label (our code, not arbitrary).
    unsafe {
        let state_ptr = SIGNAL_STATE.with(|cell| cell.get());
        if state_ptr.is_null() {
            delegate_to_previous(signum, _siginfo, ucontext);
            return;
        }
        let state = &*state_ptr;

        // Read faulting PC from ucontext.
        let cx = &mut *(ucontext as *mut libc::ucontext_t);
        let pc = cx.uc_mcontext.gregs[libc::REG_RIP as usize] as usize;

        // Check if the faulting PC is within our JIT code region.
        if pc < state.code_start || pc >= state.code_end {
            delegate_to_previous(signum, _siginfo, ucontext);
            return;
        }

        // The guest's fault only at a guest access's own instruction, on
        // an address in its window; anything else is the backend's.
        let fault_host = (*_siginfo).si_addr() as usize;
        let fault_offset = fault_host.wrapping_sub(state.window_base);
        let native_offset = (pc - state.code_start) as u32;
        let trap_table = std::slice::from_raw_parts(state.trap_table_ptr, state.trap_table_len);
        let attributed = trap_table
            .binary_search_by_key(&native_offset, |&(off, _)| off)
            .ok()
            .filter(|_| fault_offset < 1 << 32);
        let Some(entry) = attributed else {
            // A second fault while aborting, or one before the entry
            // recorded its frame, has no frame to return through.
            if state.backend_fault.get() || state.entry_rsp == 0 {
                delegate_to_previous(signum, _siginfo, ucontext);
                return;
            }
            state.backend_fault.set(true);
            cx.uc_mcontext.gregs[libc::REG_RSP as usize] = state.entry_rsp as i64;
            cx.uc_mcontext.gregs[libc::REG_RIP as usize] = state.abort_label_addr as i64;
            return;
        };
        let pvm_pc = trap_table[entry].1;

        // A write may be the first into a slot that does not track writes
        // yet. The x86 page-fault error code's bit 1 marks a write.
        let ctx = &mut *state.ctx_ptr;
        let write = cx.uc_mcontext.gregs[libc::REG_ERR as usize] & 2 != 0;
        if write && !state.activation.is_null() {
            // Starting tracking makes system calls; keep the interrupted
            // code's errno.
            let errno = *libc::__errno_location();
            let activated = (*state.activation).activate(fault_offset / 4096);
            *libc::__errno_location() = errno;
            match activated {
                Activated::Started => return,
                Activated::Failed => {
                    // A backend failure, not a guest exit: the invocation
                    // aborts, and the context's pc is not meaningful.
                    ctx.exit_reason = EXIT_TRACKING_FAILED;
                    ctx.fast_reentry = 0;
                    cx.uc_mcontext.gregs[libc::REG_RIP as usize] = state.exit_label_addr as i64;
                    return;
                }
                Activated::NotTracking => {}
            }
        }

        // Guest fault address = faulting host address (si_addr) relative to
        // the guest memory base, masked to the page base. si_addr identifies
        // the actual faulting page — unlike RDX (the access's base address),
        // which points at the previous page when an unaligned access
        // straddles into a protected page. Page-granular fault addresses
        // match the interpreter and the Lean oracle.
        let guest_addr = (fault_offset as u32) & !0xFFF;

        // Write trap info into JitContext.
        ctx.exit_reason = EXIT_PAGE_FAULT;
        ctx.exit_arg = u64::from(guest_addr);
        ctx.pc = pvm_pc;
        ctx.fast_reentry = 0;
        if (pvm_pc as usize) < state.fault_resume_offsets_len {
            let offset = *state.fault_resume_offsets_ptr.add(pvm_pc as usize);
            if offset >= 0 {
                // Zero means no fast re-entry; store offset+1 as a one-shot
                // native instruction cursor consumed by the prologue.
                ctx.fast_reentry = (offset as u32).saturating_add(1);
            }
        }

        // Redirect execution to exit_label (saves regs + ret to Rust).
        cx.uc_mcontext.gregs[libc::REG_RIP as usize] = state.exit_label_addr as i64;
    }
}

/// Hand the signal to the handler [`install_handler`] replaced.
///
/// # Safety
///
/// Called from [`sigsegv_handler`] with the arguments it was given, after
/// `install_handler` ran.
unsafe fn delegate_to_previous(
    signum: libc::c_int,
    siginfo: *mut libc::siginfo_t,
    context: *mut libc::c_void,
) {
    // SAFETY: PREV_SIGSEGV was initialized by install_handler (protected by Once).
    // The transmute calls convert the sa_sigaction field to the appropriate function
    // pointer type based on SA_SIGINFO flag — matching how the OS would call it.
    // If the previous handler is SIG_DFL/SIG_IGN, we restore it and let the
    // signal re-fire with default behavior (typically process termination).
    unsafe {
        let prev = PREV_SIGSEGV;
        if prev.sa_flags & libc::SA_SIGINFO != 0 {
            let handler: extern "C" fn(libc::c_int, *mut libc::siginfo_t, *mut libc::c_void) =
                std::mem::transmute(prev.sa_sigaction);
            handler(signum, siginfo, context);
        } else if prev.sa_sigaction == libc::SIG_DFL || prev.sa_sigaction == libc::SIG_IGN {
            // Restore default handler and let the signal re-fire.
            libc::sigaction(signum, &prev, null_mut());
        } else {
            let handler: extern "C" fn(libc::c_int) = std::mem::transmute(prev.sa_sigaction);
            handler(signum);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A thread's alternate signal stack is unmapped when the thread exits,
    /// so threads that ran native code leave no mapping behind. The stack
    /// is marked before the thread exits: after, its address reads as
    /// unmapped, or (another test thread's mapping landing on the freed
    /// range) as memory that does not hold the mark.
    #[test]
    fn a_threads_alternate_stack_leaves_with_it() {
        const MARK: [u8; 16] = *b"alternate-stack!";
        let stack = std::thread::spawn(|| {
            ensure_installed().unwrap();
            // SAFETY: sigaltstack writes the current stack into a valid struct.
            let mut current: libc::stack_t = unsafe { std::mem::zeroed() };
            assert_eq!(unsafe { libc::sigaltstack(null_mut(), &mut current) }, 0);
            assert_eq!(current.ss_flags & libc::SS_DISABLE, 0);
            assert!(current.ss_size >= MARK.len());
            // SAFETY: the alternate stack is this thread's, mapped and
            // writable for `ss_size` bytes, and unused while no signal runs.
            unsafe {
                std::ptr::copy_nonoverlapping(MARK.as_ptr(), current.ss_sp as *mut u8, MARK.len())
            };
            current.ss_sp as usize
        })
        .join()
        .unwrap();
        let mut pipe = [0; 2];
        let mut read = [0u8; 16];
        // SAFETY: pipe fills a valid array; write reads the bytes at `stack`
        // in the kernel, which reports an unmapped address as EFAULT; read
        // fills `read`.
        let wrote = unsafe {
            assert_eq!(libc::pipe(pipe.as_mut_ptr()), 0);
            let wrote = libc::write(pipe[1], stack as *const libc::c_void, MARK.len());
            if wrote == MARK.len() as isize {
                libc::read(pipe[0], read.as_mut_ptr() as *mut libc::c_void, MARK.len());
            }
            libc::close(pipe[0]);
            libc::close(pipe[1]);
            wrote
        };
        assert!(
            wrote == -1 || read != MARK,
            "the exited thread's stack is unmapped"
        );
    }
}
