//! Fuzz target: arbitrary bytes as an actor's linked ELF through
//! `vos_pvm_compiler::derive`, which a node runs on the ELF of a program it
//! is given to install. Seeded with the compiler's test ELF and the
//! guests built in this checkout (`cargo run --example seed`).
//!
//! Properties: **no panic, no abort**, within the recipes' memory and time
//! bounds (`-rss_limit_mb=512 -timeout=10`: a bound on what derive
//! allocates and walks, whatever the ELF claims), and **derive is a
//! function of its bytes:** a second derive of the same bytes is the
//! first's.

#![no_main]

use libfuzzer_sys::fuzz_target;
use vos_pvm_compiler::derive;

fuzz_target!(|data: &[u8]| {
    if let Ok(derived) = derive(data) {
        assert_eq!(
            derive(data).ok().as_ref(),
            Some(&derived),
            "derive is a function of its bytes"
        );
    }
});
