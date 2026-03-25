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

use crate::syscall_handler::SyscallArgs;
use pvx_abi::actor::ActorId;

/// A virtual file descriptor entry.
#[derive(Debug)]
pub enum VfdKind {
    /// /dev/null — reads return EOF, writes are discarded.
    Null,
    /// In-memory ring buffer. Used for stdout/stderr capture and pipes.
    Buffer {
        /// Write position.
        len: usize,
        /// Read position.
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
    /// Index into VirtualFs::buffers for Buffer fds. Unused for other kinds.
    buf_idx: Option<usize>,
}

/// Virtual filesystem managing fd tables across all actors.
///
/// Fixed capacity. `MAX_FDS` file descriptors, `MAX_BUFS` backing buffers
/// of `BUF_SIZE` bytes each.
pub struct VirtualFs<
    const MAX_FDS: usize = 64,
    const MAX_BUFS: usize = 16,
    const BUF_SIZE: usize = 4096,
> {
    fds: [Option<FdEntry>; MAX_FDS],
    buffers: [[u8; BUF_SIZE]; MAX_BUFS],
    buf_used: [bool; MAX_BUFS],
}

impl<const MAX_FDS: usize, const MAX_BUFS: usize, const BUF_SIZE: usize> Default
    for VirtualFs<MAX_FDS, MAX_BUFS, BUF_SIZE>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<const MAX_FDS: usize, const MAX_BUFS: usize, const BUF_SIZE: usize>
    VirtualFs<MAX_FDS, MAX_BUFS, BUF_SIZE>
{
    const NONE_FD: Option<FdEntry> = None;

    pub fn new() -> Self {
        Self {
            fds: [Self::NONE_FD; MAX_FDS],
            buffers: [[0u8; BUF_SIZE]; MAX_BUFS],
            buf_used: [false; MAX_BUFS],
        }
    }

    /// Allocate a backing buffer. Returns index or None.
    fn alloc_buf(&mut self) -> Option<usize> {
        for (i, used) in self.buf_used.iter_mut().enumerate() {
            if !*used {
                *used = true;
                self.buffers[i] = [0u8; BUF_SIZE];
                return Some(i);
            }
        }
        None
    }

    /// Free a backing buffer.
    fn free_buf(&mut self, idx: usize) {
        if idx < MAX_BUFS {
            self.buf_used[idx] = false;
        }
    }

    /// Allocate a new fd for an actor. Returns fd number or negative errno.
    fn alloc_fd(&mut self, owner: ActorId, kind: VfdKind) -> i64 {
        let buf_idx = if matches!(kind, VfdKind::Buffer { .. }) {
            match self.alloc_buf() {
                Some(i) => Some(i),
                None => return pvx_abi::syscall::errno::ENOMEM as i64,
            }
        } else {
            None
        };

        for (i, slot) in self.fds.iter_mut().enumerate() {
            if slot.is_none() {
                *slot = Some(FdEntry {
                    owner,
                    kind,
                    buf_idx,
                });
                return i as i64;
            }
        }
        // No fd slot available — free the buffer we allocated
        if let Some(bi) = buf_idx {
            self.free_buf(bi);
        }
        pvx_abi::syscall::errno::ENOMEM as i64
    }

    /// Set up default fds for a new actor (stdin=null, stdout=buffer, stderr=buffer).
    pub fn init_actor(&mut self, id: ActorId) -> [i32; 3] {
        let stdin = self.alloc_fd(id, VfdKind::Null) as i32;
        let stdout = self.alloc_fd(
            id,
            VfdKind::Buffer {
                len: 0,
                read_pos: 0,
            },
        ) as i32;
        let stderr = self.alloc_fd(
            id,
            VfdKind::Buffer {
                len: 0,
                read_pos: 0,
            },
        ) as i32;
        [stdin, stdout, stderr]
    }

    pub fn open(&mut self, caller: ActorId, args: &SyscallArgs) -> i64 {
        let _ = (args.a0, args.a1); // path_ptr, path_len
        self.alloc_fd(caller, VfdKind::Null)
    }

    pub fn read(&mut self, caller: ActorId, args: &SyscallArgs) -> i64 {
        let fd = args.a0 as usize;
        let _buf_ptr = args.a1;
        let buf_len = args.a2 as usize;

        let entry = match self.fds.get_mut(fd) {
            Some(Some(e)) if e.owner == caller => e,
            _ => return pvx_abi::syscall::errno::EBADF as i64,
        };

        match &mut entry.kind {
            VfdKind::Null => 0, // EOF
            VfdKind::Buffer { len, read_pos } => {
                let available = *len - *read_pos;
                let to_read = available.min(buf_len);
                // In real impl: copy from backing buffer to child memory
                *read_pos += to_read;
                to_read as i64
            }
            VfdKind::Closed => pvx_abi::syscall::errno::EBADF as i64,
        }
    }

    pub fn write(&mut self, caller: ActorId, args: &SyscallArgs) -> i64 {
        let fd = args.a0 as usize;
        let _buf_ptr = args.a1;
        let buf_len = args.a2 as usize;

        let entry = match self.fds.get_mut(fd) {
            Some(Some(e)) if e.owner == caller => e,
            _ => return pvx_abi::syscall::errno::EBADF as i64,
        };

        match &mut entry.kind {
            VfdKind::Null => buf_len as i64, // discard
            VfdKind::Buffer { len, .. } => {
                let space = BUF_SIZE - *len;
                let to_write = space.min(buf_len);
                // In real impl: copy from child memory to backing buffer
                *len += to_write;
                to_write as i64
            }
            VfdKind::Closed => pvx_abi::syscall::errno::EBADF as i64,
        }
    }

    pub fn close(&mut self, caller: ActorId, args: &SyscallArgs) -> i64 {
        let fd = args.a0 as usize;
        let entry = match self.fds.get_mut(fd) {
            Some(Some(e)) if e.owner == caller => e,
            _ => return pvx_abi::syscall::errno::EBADF as i64,
        };
        let buf_idx = entry.buf_idx.take();
        entry.kind = VfdKind::Closed;
        if let Some(bi) = buf_idx {
            self.free_buf(bi);
        }
        0
    }

    pub fn seek(&mut self, caller: ActorId, args: &SyscallArgs) -> i64 {
        let fd = args.a0 as usize;
        match self.fds.get(fd) {
            Some(Some(e)) if e.owner == caller => {
                let _ = (args.a1, args.a2); // offset, whence
                pvx_abi::syscall::errno::EINVAL as i64 // not seekable yet
            }
            _ => pvx_abi::syscall::errno::EBADF as i64,
        }
    }

    pub fn poll(&mut self, caller: ActorId, args: &SyscallArgs) -> i64 {
        let _ = (caller, args);
        0
    }
}
