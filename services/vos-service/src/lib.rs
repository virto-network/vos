//! Generic VOS v2 JAM service guest.
//!
//! The ELF exports the Gray Paper's two physical entries. `_start` is Refine
//! (IC 0 after transpilation) and `accumulate` is Accumulate (IC 5). Registers
//! `a0`/`a1` remain the standard argument pointer/length window; no register is
//! used as a VOS phase selector.

#[cfg(target_arch = "riscv64")]
mod guest {

    use core::arch::global_asm;

    use vos::abi::pvm::hostcalls;
    use vos::v2::{TransitionV2, V2Wire, WorkEnvelopeV2};

    /// Upper bound for one nested actor transition in this foundation guest. This
    /// lives in zero-initialized guest memory rather than the small application
    /// allocator. Oversize output fails the work item; it is never truncated.
    const TRANSITION_CAPACITY: usize = 4 * 1024 * 1024;
    const SERVICE_GAS_RESERVE: u64 = 100_000;

    #[unsafe(link_section = ".bss.vos_service_transition")]
    static mut TRANSITION_BUFFER: [u8; TRANSITION_CAPACITY] = [0; TRANSITION_CAPACITY];

    #[repr(C)]
    struct OutputWindow {
        address: u64,
        len: u64,
    }

    // The transpiler emits the physical two-jump GP prologue from these exported
    // ELF symbols. The host installs the halt address in `ra`; each successful
    // entry returns to it after its Rust body produces the output window.
    global_asm!(
        ".global _start",
        ".type _start, @function",
        "_start:",
        "mv s0, ra",
        "jal ra, vos_service_refine",
        "mv ra, s0",
        "ret",
        ".global accumulate",
        ".type accumulate, @function",
        "accumulate:",
        "mv s0, ra",
        "jal ra, vos_service_accumulate",
        "mv ra, s0",
        "ret",
    );

    /// Run one pure actor-tree slice. The supplied INVOKE capability is a
    /// mechanical nested-JAR scheduler: it receives the exact work bytes and the
    /// target canonical ProgramId, and returns the actor-produced TransitionV2.
    #[unsafe(no_mangle)]
    extern "C" fn vos_service_refine(arguments: *const u8, arguments_len: usize) -> OutputWindow {
        // SAFETY: JAM initializes a readable argument window at (a0, a1).
        let input = unsafe { core::slice::from_raw_parts(arguments, arguments_len) };
        let work = WorkEnvelopeV2::decode(input).unwrap_or_else(|_| fail_closed());
        if work.service.service_abi != vos::v2::ABI_VERSION
            || work.service.execution_semantics != vos::v2::EXECUTION_SEMANTICS_ID
            || !work.base.mode_compatible(work.consistency)
        {
            fail_closed();
        }

        let output_address = core::ptr::addr_of_mut!(TRANSITION_BUFFER).cast::<u8>();
        // SAFETY: the PVM is single-threaded and the buffer is exclusively used by
        // this invocation until the terminal halt reads it.
        let output =
            unsafe { core::slice::from_raw_parts_mut(output_address, TRANSITION_CAPACITY) };
        let nested_gas = hostcalls::gas().saturating_sub(SERVICE_GAS_RESERVE);
        let produced =
            hostcalls::invoke(&work.target_program.0, input, nested_gas, output) as usize;
        if produced > output.len() {
            fail_closed();
        }

        let transition =
            TransitionV2::decode(&output[..produced]).unwrap_or_else(|_| fail_closed());
        if transition.service != work.service
            || transition.consumed_input != work.invocation
            || transition.target_program != work.target_program
            || transition.base != work.base
        {
            fail_closed();
        }
        drop(transition);

        OutputWindow {
            address: output_address as u64,
            len: produced as u64,
        }
    }

    /// Accumulate remains fail-closed until the guest storage transaction logic is
    /// implemented. Keeping the physical symbol present lets every build verify
    /// the IC-5 entry without ever treating a no-op as a successful commit.
    #[unsafe(no_mangle)]
    extern "C" fn vos_service_accumulate(
        _arguments: *const u8,
        _arguments_len: usize,
    ) -> OutputWindow {
        fail_closed()
    }

    #[cold]
    fn fail_closed() -> ! {
        // The transpiler maps RISC-V EBREAK to the GP trap instruction, so an
        // invalid work item fails immediately instead of burning its gas in a
        // loop or accidentally returning an empty successful transition.
        unsafe {
            core::arch::asm!("ebreak", options(noreturn, nostack));
        }
    }
}
