//! Panic handler for guest actors.

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    use core::fmt::Write;
    struct PanicWriter;
    impl core::fmt::Write for PanicWriter {
        fn write_str(&mut self, s: &str) -> core::fmt::Result {
            pvx_scape::io::pvm_write(2, s.as_ptr(), s.len());
            Ok(())
        }
    }
    let _ = write!(PanicWriter, "panic: {}\n", info);
    loop {}
}
