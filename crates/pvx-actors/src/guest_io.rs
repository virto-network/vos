//! I/O macros for guest actors — print!/println!/eprint!/eprintln! backed by PVM syscalls.

/// Print to stdout via PVM FdWrite syscall.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        struct __PvxStdout;
        impl core::fmt::Write for __PvxStdout {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                $crate::__io::pvm_write(1, s.as_ptr(), s.len());
                Ok(())
            }
        }
        let _ = core::write!(__PvxStdout, $($arg)*);
    }};
}

/// Print to stdout with a newline.
#[macro_export]
macro_rules! println {
    () => { $crate::print!("\n") };
    ($($arg:tt)*) => {{
        $crate::print!($($arg)*);
        $crate::print!("\n");
    }};
}

/// Print to stderr via PVM FdWrite syscall.
#[macro_export]
macro_rules! eprint {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        struct __PvxStderr;
        impl core::fmt::Write for __PvxStderr {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                $crate::__io::pvm_write(2, s.as_ptr(), s.len());
                Ok(())
            }
        }
        let _ = core::write!(__PvxStderr, $($arg)*);
    }};
}

/// Print to stderr with a newline.
#[macro_export]
macro_rules! eprintln {
    () => { $crate::eprint!("\n") };
    ($($arg:tt)*) => {{
        $crate::eprint!($($arg)*);
        $crate::eprint!("\n");
    }};
}
