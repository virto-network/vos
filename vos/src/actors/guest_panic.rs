//! Panic handler for guest actors.

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    #[cfg(not(all(target_arch = "riscv64", feature = "agent-runtime")))]
    report(_info);

    // A guest panic is a terminal PVM condition. RISC-V EBREAK transpiles to
    // the GP trap opcode, so the invocation fails deterministically instead
    // of consuming its remaining gas in a loop. AgentRuntime deliberately
    // reaches this trap without formatting or invoking DEBUG_WRITE: its outer
    // host-call surface is restricted to the standard inner-machine calls.
    unsafe {
        core::arch::asm!("ebreak", options(noreturn, nostack));
    }
}

#[cfg(not(all(target_arch = "riscv64", feature = "agent-runtime")))]
fn report(info: &core::panic::PanicInfo<'_>) {
    use core::fmt::Write;
    struct PanicWriter;
    impl core::fmt::Write for PanicWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            crate::abi::pvm::hostcalls::debug_write(s.as_bytes());
            Ok(())
        }
    }
    let _ = write!(PanicWriter, "panic: {}\n", info);
}
