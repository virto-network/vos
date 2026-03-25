//! Shared runtime for example PVM actors.

#![no_std]

use core::panic::PanicInfo;

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}

/// Write a byte slice to stdout.
#[inline(never)]
pub fn print(s: &[u8]) {
    pvx_scape::io::pvm_write(1, s.as_ptr(), s.len());
}

/// Write a byte slice to stdout followed by a newline.
#[inline(never)]
pub fn println(s: &[u8]) {
    print(s);
    print(b"\n");
}

/// Print a single digit 0-9.
#[inline(never)]
pub fn print_digit(n: u8) {
    let c = b'0' + n;
    pvx_scape::io::pvm_write(1, &c as *const u8, 1);
}
