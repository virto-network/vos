//! File descriptor I/O — libc-compatible wrappers.
//!
//! These mirror the POSIX file I/O interface. The executor maps
//! fd numbers to virtual resources (buffers, pipes, etc.) via the VFS.
//!
//! The `#[unsafe(no_mangle)]` symbols are only emitted on RISC-V targets
//! to avoid conflicts with the host libc during development/testing.

use crate::syscall::{syscall1, syscall2, syscall3};
use pvx_abi::syscall::Syscall;

/// Write `len` bytes from `buf` to file descriptor `fd`.
/// Returns bytes written or negative errno.
#[cfg_attr(target_arch = "riscv64", unsafe(no_mangle))]
pub extern "C" fn pvm_write(fd: i32, buf: *const u8, len: usize) -> isize {
    syscall3(Syscall::FdWrite, fd as i64, buf as i64, len as i64) as isize
}

/// Read up to `len` bytes from file descriptor `fd` into `buf`.
/// Returns bytes read, 0 on EOF, or negative errno.
#[cfg_attr(target_arch = "riscv64", unsafe(no_mangle))]
pub extern "C" fn pvm_read(fd: i32, buf: *mut u8, len: usize) -> isize {
    syscall3(Syscall::FdRead, fd as i64, buf as i64, len as i64) as isize
}

/// Close a file descriptor.
#[cfg_attr(target_arch = "riscv64", unsafe(no_mangle))]
pub extern "C" fn pvm_close(fd: i32) -> i32 {
    syscall1(Syscall::FdClose, fd as i64) as i32
}

/// Yield execution to the executor, allowing other actors to run.
#[inline]
pub fn yield_now() {
    syscall1(Syscall::Yield, 0);
}

/// Get the current actor's ID.
#[inline]
pub fn self_id() -> u32 {
    syscall1(Syscall::SelfId, 0) as u32
}

/// Send a message to another actor.
/// Returns 0 on success, negative errno on failure.
#[inline]
pub fn send(target: u32, msg: &[u8]) -> i32 {
    syscall3(
        Syscall::Send,
        target as i64,
        msg.as_ptr() as i64,
        msg.len() as i64,
    ) as i32
}

/// Receive the next pending message into `buf`.
/// Returns bytes written, 0 if no message, negative on error.
#[inline]
pub fn recv(buf: &mut [u8]) -> i32 {
    syscall2(Syscall::Recv, buf.as_mut_ptr() as i64, buf.len() as i64) as i32
}

/// Request a state checkpoint — the executor persists the actor's PVM snapshot.
/// Returns 0 on success.
#[inline]
pub fn checkpoint() -> i32 {
    syscall1(Syscall::Checkpoint, 0) as i32
}
