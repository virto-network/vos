//! Panic handler for guest actors.

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    struct PanicWriter;
    impl core::fmt::Write for PanicWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            crate::abi::pvm::hostcalls::debug_write(s.as_bytes());
            Ok(())
        }
    }
    let _ = write!(PanicWriter, "panic: {}\n", info);
    // A guest panic is a terminal PVM condition. RISC-V EBREAK transpiles to
    // the GP trap opcode, so the invocation fails deterministically instead
    // of consuming its remaining gas in a loop.
    unsafe {
        core::arch::asm!("ebreak", options(noreturn, nostack));
    }
}
