//! Virtual filesystem — maps file descriptors to resources.
//!
//! The executor provides a virtual fd table for each child actor.
//! This enables `std`-compatible I/O without real kernel file descriptors.
//!
//! Supported resource types:
//! - **Pipe**: unidirectional byte stream between two actors
//! - **Buffer**: in-memory byte buffer (for stdin/stdout capture)
//! - **Null**: /dev/null equivalent
//!
//! Future: real file I/O (proxied through the host), network sockets.

use pvm_abi::actor::ActorId;
use crate::syscall_handler::SyscallArgs;

/// A virtual file descriptor entry.
#[derive(Debug)]
pub enum VfdKind {
    /// /dev/null — reads return EOF, writes are discarded.
    Null,
    /// In-memory buffer. Used for stdout/stderr capture.
    Buffer {
        data: [u8; 4096],
        len: usize,
        read_pos: usize,
    },
    /// Closed / available slot.
    Closed,
}

/// Per-actor fd table entry.
#[derive(Debug)]
struct FdEntry {
    owner: ActorId,
    kind: VfdKind,
}

/// Virtual filesystem managing fd tables across all actors.
///
/// Fixed capacity. Each actor gets fds from a shared pool.
pub struct VirtualFs {
    fds: [Option<FdEntry>; Self::MAX_FDS],
}

impl VirtualFs {
    const MAX_FDS: usize = 64;
    const NONE: Option<FdEntry> = None;

    pub fn new() -> Self {
        Self {
            fds: [Self::NONE; Self::MAX_FDS],
        }
    }

    /// Allocate a new fd for an actor. Returns fd number or negative errno.
    fn alloc_fd(&mut self, owner: ActorId, kind: VfdKind) -> i64 {
        for (i, slot) in self.fds.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(FdEntry { owner, kind });
                return i as i64;
            }
        }
        pvm_abi::syscall::errno::ENOMEM as i64
    }

    /// Set up default fds for a new actor (stdin=null, stdout=buffer, stderr=buffer).
    pub fn init_actor(&mut self, id: ActorId) -> [i32; 3] {
        let stdin = self.alloc_fd(id, VfdKind::Null) as i32;
        let stdout = self.alloc_fd(
            id,
            VfdKind::Buffer {
                data: [0; 4096],
                len: 0,
                read_pos: 0,
            },
        ) as i32;
        let stderr = self.alloc_fd(
            id,
            VfdKind::Buffer {
                data: [0; 4096],
                len: 0,
                read_pos: 0,
            },
        ) as i32;
        [stdin, stdout, stderr]
    }

    pub fn open(&mut self, caller: ActorId, args: &SyscallArgs) -> i64 {
        // For now, only support opening /dev/null
        let _ = (args.a0, args.a1); // path_ptr, path_len
        self.alloc_fd(caller, VfdKind::Null)
    }

    pub fn read(&mut self, caller: ActorId, args: &SyscallArgs) -> i64 {
        let fd = args.a0 as usize;
        let _buf_ptr = args.a1;
        let buf_len = args.a2 as usize;

        let entry = match self.fds.get_mut(fd) {
            Some(Some(e)) if e.owner == caller => e,
            _ => return pvm_abi::syscall::errno::EBADF as i64,
        };

        match &mut entry.kind {
            VfdKind::Null => 0, // EOF
            VfdKind::Buffer {
                data,
                len,
                read_pos,
            } => {
                let available = *len - *read_pos;
                let to_read = available.min(buf_len);
                // In real impl: copy data[read_pos..read_pos+to_read] to child memory
                *read_pos += to_read;
                let _ = data; // used when we have memory access
                to_read as i64
            }
            VfdKind::Closed => pvm_abi::syscall::errno::EBADF as i64,
        }
    }

    pub fn write(&mut self, caller: ActorId, args: &SyscallArgs) -> i64 {
        let fd = args.a0 as usize;
        let _buf_ptr = args.a1;
        let buf_len = args.a2 as usize;

        let entry = match self.fds.get_mut(fd) {
            Some(Some(e)) if e.owner == caller => e,
            _ => return pvm_abi::syscall::errno::EBADF as i64,
        };

        match &mut entry.kind {
            VfdKind::Null => buf_len as i64, // discard
            VfdKind::Buffer { data, len, .. } => {
                let space = data.len() - *len;
                let to_write = space.min(buf_len);
                // In real impl: copy from child memory to data[len..len+to_write]
                *len += to_write;
                to_write as i64
            }
            VfdKind::Closed => pvm_abi::syscall::errno::EBADF as i64,
        }
    }

    pub fn close(&mut self, caller: ActorId, args: &SyscallArgs) -> i64 {
        let fd = args.a0 as usize;
        match self.fds.get_mut(fd) {
            Some(Some(e)) if e.owner == caller => {
                e.kind = VfdKind::Closed;
                0
            }
            _ => pvm_abi::syscall::errno::EBADF as i64,
        }
    }

    pub fn seek(&mut self, caller: ActorId, args: &SyscallArgs) -> i64 {
        let fd = args.a0 as usize;
        match self.fds.get(fd) {
            Some(Some(e)) if e.owner == caller => {
                let _ = (args.a1, args.a2); // offset, whence
                pvm_abi::syscall::errno::EINVAL as i64 // not seekable yet
            }
            _ => pvm_abi::syscall::errno::EBADF as i64,
        }
    }

    pub fn poll(&mut self, caller: ActorId, args: &SyscallArgs) -> i64 {
        let _ = (caller, args);
        // TODO: implement when we have pipe-based inter-actor I/O
        0
    }
}
