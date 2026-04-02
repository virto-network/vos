//! Panic handler for guest actors.

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    struct PanicWriter;
    impl core::fmt::Write for PanicWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            vos_abi::pvm::hostcalls::debug_write(s.as_bytes());
            Ok(())
        }
    }
    let _ = write!(PanicWriter, "panic: {}\n", info);
    loop {}
}
