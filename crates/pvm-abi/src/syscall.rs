//! Syscall ABI — "system calls" that child actors make to the executor.
//!
//! When a child actor needs I/O or wants to communicate with other actors,
//! it invokes a syscall. In PVM, this is a host function call. The executor
//! handles it and returns the result.
//!
//! This module defines the syscall numbers and argument conventions.
//! `pvm-scape` uses these to implement libc-compatible wrappers so that
//! `std`-dependent code works transparently in child actors.
//!
//! ```text
//! Child actor
//!     │
//!     ├─ send(target, msg)     → deliver message to another actor
//!     ├─ recv(buf)             → receive next message (blocking/async)
//!     ├─ fd_open(path, flags)  → open a virtual file descriptor
//!     ├─ fd_read(fd, buf)      → read from fd
//!     ├─ fd_write(fd, buf)     → write to fd
//!     ├─ fd_close(fd)          → close fd
//!     ├─ fd_poll(fds, n)       → poll multiple fds (epoll-like)
//!     ├─ log(level, msg)       → structured logging
//!     └─ yield()               → explicitly yield to executor
//! ```

/// Syscall numbers. Each maps to a host-imported function.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Syscall {
    // -- Actor messaging --
    /// Send a message to another actor.
    /// Args: (target: ActorId, msg_ptr: *const u8, msg_len: u32) -> i32
    Send = 1,

    /// Receive the next pending message (non-blocking).
    /// Args: (buf_ptr: *mut u8, buf_len: u32) -> i32
    /// Returns: bytes written, 0 if no message, negative on error.
    Recv = 2,

    // -- File descriptor operations --
    // These enable std-compatible I/O. The executor maps fds to
    // virtual resources (files, pipes between actors, network, etc.)

    /// Open a file descriptor.
    /// Args: (path_ptr: *const u8, path_len: u32, flags: u32) -> i32
    /// Returns: fd number, or negative errno.
    FdOpen = 10,

    /// Read from a file descriptor.
    /// Args: (fd: i32, buf_ptr: *mut u8, buf_len: u32) -> i32
    /// Returns: bytes read, 0 on EOF, negative errno.
    FdRead = 11,

    /// Write to a file descriptor.
    /// Args: (fd: i32, buf_ptr: *const u8, buf_len: u32) -> i32
    /// Returns: bytes written, negative errno.
    FdWrite = 12,

    /// Close a file descriptor.
    /// Args: (fd: i32) -> i32
    FdClose = 13,

    /// Poll file descriptors for readiness (epoll-like).
    /// Args: (events_ptr: *mut PollEvent, n_events: u32, timeout_ms: i32) -> i32
    /// Returns: number of ready fds, 0 on timeout, negative errno.
    FdPoll = 14,

    /// Seek within a file descriptor.
    /// Args: (fd: i32, offset: i64, whence: u32) -> i64
    FdSeek = 15,

    // -- Utilities --

    /// Structured log output.
    /// Args: (level: u32, msg_ptr: *const u8, msg_len: u32) -> i32
    Log = 30,

    /// Yield execution back to the executor. Equivalent to an async
    /// yield point — lets other actors run.
    /// Args: () -> ()
    Yield = 31,

    /// Get the current actor's ID.
    /// Args: () -> u32
    SelfId = 32,

    /// Get monotonic time in microseconds.
    /// Args: () -> u64
    Now = 33,
}

/// Poll event for `FdPoll` syscall.
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct PollEvent {
    /// File descriptor to poll.
    pub fd: i32,
    /// Requested events (bitmask).
    pub events: u16,
    /// Returned events (filled by executor).
    pub revents: u16,
}

/// Event flags for `PollEvent`.
pub mod event_flags {
    /// Data available to read.
    pub const POLLIN: u16 = 0x01;
    /// Ready for writing.
    pub const POLLOUT: u16 = 0x04;
    /// Error condition.
    pub const POLLERR: u16 = 0x08;
    /// Hang up.
    pub const POLLHUP: u16 = 0x10;
}

/// Log levels for the `Log` syscall.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogLevel {
    Error = 1,
    Warn = 2,
    Info = 3,
    Debug = 4,
    Trace = 5,
}

/// Standard errno-style error codes returned by fd syscalls.
pub mod errno {
    pub const ENOENT: i32 = -2;
    pub const EIO: i32 = -5;
    pub const EBADF: i32 = -9;
    pub const EAGAIN: i32 = -11;
    pub const ENOMEM: i32 = -12;
    pub const EACCES: i32 = -13;
    pub const EINVAL: i32 = -22;
    pub const ENOSYS: i32 = -38;
    pub const EMSGSIZE: i32 = -90;
}
