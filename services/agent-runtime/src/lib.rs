//! Bundled VOS agent-runtime guest.
//!
//! `_start` is the stable clean-generation entry. The node supplies exactly
//! one canonical [`RuntimeWork`](vos::agent_sdk::RuntimeWork) and receives a
//! canonical [`RuntimeTransition`](vos::agent_sdk::RuntimeTransition). The
//! host persists the returned lane components without interpreting them.

#[cfg(target_arch = "riscv64")]
mod guest {
    extern crate alloc;

    use alloc::vec::Vec;
    use core::arch::global_asm;

    use vos::agent::wire::apply_standard_runtime_work;
    use vos::agent_sdk::wire::CanonicalWire as _;

    #[repr(C)]
    struct OutputWindow {
        address: u64,
        len: u64,
    }

    global_asm!(
        ".global _start",
        ".type _start, @function",
        "_start:",
        "mv s0, ra",
        "jal ra, vos_agent_manage",
        "mv ra, s0",
        "ret",
    );

    #[unsafe(no_mangle)]
    extern "C" fn vos_agent_manage(arguments: *const u8, arguments_len: usize) -> OutputWindow {
        // SAFETY: the standard PVM loader maps the complete argument window
        // read-only and supplies its base/length in a0/a1.
        let input = unsafe { core::slice::from_raw_parts(arguments, arguments_len) };
        let work = vos::agent_sdk::RuntimeWork::decode(input).unwrap_or_else(|_| fail_closed());
        let output = apply_standard_runtime_work(work)
            .unwrap_or_else(|_| fail_closed())
            .encode()
            .unwrap_or_else(|_| fail_closed());
        return_owned(output)
    }

    fn return_owned(output: Vec<u8>) -> OutputWindow {
        let window = OutputWindow {
            address: output.as_ptr() as u64,
            len: output.len() as u64,
        };
        // The invocation halts immediately after returning to `_start`, so
        // the allocator-owned bytes must remain live for the host to copy.
        core::mem::forget(output);
        window
    }

    fn fail_closed() -> ! {
        // An invalid management call is a deterministic guest trap, never an
        // empty or partially decoded success.
        unsafe { core::arch::asm!("ebreak", options(noreturn, nostack)) }
    }
}
