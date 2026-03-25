//! Syscall handler — processes syscalls from child actors.
//!
//! When a child actor makes a syscall (via host-imported functions),
//! the executor routes it here. The handler implements the actual
//! operations: message routing, virtual file I/O, logging, etc.
//!
//! **Send/Recv** syscalls are handled at the scheduler level since
//! they need access to the actor registry. The handler returns
//! [`SyscallResult::Send`]/[`SyscallResult::Recv`] to signal the
//! scheduler to perform the routing.

use crate::vfs::VirtualFs;
use pvm_abi::actor::ActorId;
use pvm_abi::syscall::{LogLevel, Syscall};

/// Result of dispatching a syscall.
pub enum SyscallResult {
    /// Syscall handled, return this value to the caller.
    Value(i64),
    /// Send syscall — scheduler should route the message.
    /// Fields: (target ActorId, msg_ptr, msg_len)
    Send {
        target: ActorId,
        msg_ptr: i64,
        msg_len: i64,
    },
    /// Recv syscall — scheduler should deliver next pending message.
    /// Fields: (buf_ptr, buf_len)
    Recv { buf_ptr: i64, buf_len: i64 },
}

/// Trait for accessing a child actor's memory.
///
/// In a real PVM executor, this reads/writes guest memory through the
/// VM's memory interface. In tests, it can use a simple byte buffer.
pub trait MemoryAccess {
    /// Read `len` bytes from the child's memory at `ptr` into `dst`.
    /// Returns the number of bytes actually read.
    fn read_guest(&self, actor: ActorId, ptr: i64, dst: &mut [u8]) -> usize;

    /// Write `src` bytes into the child's memory at `ptr`.
    /// Returns the number of bytes actually written.
    fn write_guest(&mut self, actor: ActorId, ptr: i64, src: &[u8]) -> usize;
}

/// Handles syscalls from child actors.
pub struct SyscallHandler {
    pub vfs: VirtualFs,
}

impl Default for SyscallHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl SyscallHandler {
    pub fn new() -> Self {
        Self {
            vfs: VirtualFs::new(),
        }
    }

    /// Dispatch a syscall. Returns either a direct value or a
    /// scheduler-level action (Send/Recv).
    pub fn dispatch(
        &mut self,
        caller: ActorId,
        syscall: Syscall,
        args: &SyscallArgs,
    ) -> SyscallResult {
        match syscall {
            Syscall::Log => {
                self.handle_log(caller, args);
                SyscallResult::Value(0)
            }
            Syscall::Yield => SyscallResult::Value(0),
            Syscall::SelfId => SyscallResult::Value(caller.0 as i64),
            Syscall::Now => SyscallResult::Value(self.monotonic_now()),

            Syscall::FdOpen => SyscallResult::Value(self.vfs.open(caller, args)),
            Syscall::FdRead => SyscallResult::Value(self.vfs.read(caller, args)),
            Syscall::FdWrite => SyscallResult::Value(self.vfs.write(caller, args)),
            Syscall::FdClose => SyscallResult::Value(self.vfs.close(caller, args)),
            Syscall::FdSeek => SyscallResult::Value(self.vfs.seek(caller, args)),
            Syscall::FdPoll => SyscallResult::Value(self.vfs.poll(caller, args)),

            Syscall::Send => SyscallResult::Send {
                target: ActorId(args.a0 as u32),
                msg_ptr: args.a1,
                msg_len: args.a2,
            },
            Syscall::Recv => SyscallResult::Recv {
                buf_ptr: args.a0,
                buf_len: args.a1,
            },
        }
    }

    fn handle_log(&self, caller: ActorId, args: &SyscallArgs) {
        let _level = args.a0 as u32;
        let _msg_ptr = args.a1;
        let _msg_len = args.a2 as u32;
        // In std mode: print to stderr
        // In PVM mode: forward to host logging
        // TODO: implement when we have memory access to child
        let _ = (caller, LogLevel::Info);
    }

    fn monotonic_now(&self) -> i64 {
        // Placeholder — in real impl, query host or system clock
        0
    }
}

/// Raw syscall arguments. Up to 4 register-sized values.
#[derive(Debug, Default)]
pub struct SyscallArgs {
    pub a0: i64,
    pub a1: i64,
    pub a2: i64,
    pub a3: i64,
}
