//! I/O macros for guest actors — print!/println!/eprint!/eprintln!
//! backed by DEBUG_WRITE hostcall.
//!
//! Output is automatically suppressed during ask-replay re-dispatch
//! so that handlers don't produce duplicate output.

/// Print to debug output via DEBUG_WRITE hostcall.
/// Suppressed during ask-replay.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        if !$crate::actors::run::is_suppressing_io() {
            use core::fmt::Write;
            struct __VosDbg;
            impl core::fmt::Write for __VosDbg {
                fn write_str(&mut self, s: &str) -> core::fmt::Result {
                    $crate::__io::debug_write(s.as_bytes());
                    Ok(())
                }
            }
            let _ = core::write!(__VosDbg, $($arg)*);
        }
    }};
}

/// Print with a newline.
#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {{
        $crate::print!($($arg)*);
        $crate::print!("\n");
    }};
}

/// Print to debug output (same as print! — DEBUG_WRITE is stderr on vosx).
#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => {{
        if !$crate::actors::run::is_suppressing_io() {
            use core::fmt::Write;
            struct __VosDbgErr;
            impl core::fmt::Write for __VosDbgErr {
                fn write_str(&mut self, s: &str) -> core::fmt::Result {
                    $crate::__io::debug_write(s.as_bytes());
                    Ok(())
                }
            }
            let _ = core::write!(__VosDbgErr, $($arg)*);
        }
    }};
}

/// Print to debug output with a newline.
#[macro_export]
macro_rules! eprintln {
    () => { $crate::eprint!("\n") };
    ($($arg:tt)*) => {{
        $crate::eprint!($($arg)*);
        $crate::eprint!("\n");
    }};
}
