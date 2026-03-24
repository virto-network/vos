//! Syscall handler — processes syscalls from child actors.
//!
//! When a child actor makes a syscall (via host-imported functions),
//! the executor routes it here. The handler implements the actual
//! operations: message routing, virtual file I/O, logging, etc.

use crate::vfs::VirtualFs;
use pvm_abi::actor::ActorId;
use pvm_abi::syscall::{LogLevel, Syscall};

/// Handles syscalls from child actors.
pub struct SyscallHandler {
    pub vfs: VirtualFs,
}

impl SyscallHandler {
    pub fn new() -> Self {
        Self {
            vfs: VirtualFs::new(),
        }
    }

    /// Dispatch a syscall. Returns the result value.
    ///
    /// In a real PVM executor, this is called from the host function
    /// imports that the child program invokes. The arguments come from
    /// the child's memory.
    pub fn dispatch(
        &mut self,
        caller: ActorId,
        syscall: Syscall,
        args: &SyscallArgs,
    ) -> i64 {
        match syscall {
            Syscall::Log => {
                self.handle_log(caller, args);
                0
            }
            Syscall::Yield => 0,
            Syscall::SelfId => caller.0 as i64,
            Syscall::Now => self.monotonic_now(),

            Syscall::FdOpen => self.vfs.open(caller, args),
            Syscall::FdRead => self.vfs.read(caller, args),
            Syscall::FdWrite => self.vfs.write(caller, args),
            Syscall::FdClose => self.vfs.close(caller, args),
            Syscall::FdSeek => self.vfs.seek(caller, args),
            Syscall::FdPoll => self.vfs.poll(caller, args),

            // Send/Recv are handled at the scheduler level (needs
            // access to the registry), not here.
            Syscall::Send | Syscall::Recv => pvm_abi::syscall::errno::ENOSYS as i64,
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
