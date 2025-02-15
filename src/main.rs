#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), no_main)]

use vos::os::Os;

fn main() {
    #[cfg(feature = "std")]
    env_logger::init();
    #[cfg(feature = "web")]
    wasm_logger::init(Default::default());

    Os::boot(Default::default());
}

#[cfg(feature = "rv")]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("unimp", options(noreturn));
    }
}
