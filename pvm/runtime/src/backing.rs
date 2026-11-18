//! Native guest memory for the JIT.
//!
//! A `memfd_create` file descriptor backs a guest's memory so that the same
//! pages can be mapped twice: once into the JIT's protected 4 GiB window and
//! once as an unprotected host alias (see `recompiler::memory`).

use crate::PVM_PAGE_SIZE;

/// 4GB virtual address space per JIT window.
pub const CODE_WINDOW_SIZE: usize = 1 << 32;
/// One permission byte per 4 KiB guest page.
pub const CODE_WINDOW_PERMS_SIZE: usize = CODE_WINDOW_SIZE / PVM_PAGE_SIZE as usize;
/// Writable page holding the native JIT context.
pub const CODE_WINDOW_CTX_SIZE: usize = 4096;
/// Inaccessible span between the context and guest address 0, so that an
/// access a little below the guest window faults instead of reaching the
/// context's pointers.
pub const CODE_WINDOW_LOW_GUARD_SIZE: usize = 16 << 20;
/// Metadata prefix before guest memory, its low guard included.
pub const CODE_WINDOW_HEADER_SIZE: usize =
    CODE_WINDOW_PERMS_SIZE + CODE_WINDOW_CTX_SIZE + CODE_WINDOW_LOW_GUARD_SIZE;
/// Inaccessible span after the 32-bit guest address space.
pub const CODE_WINDOW_GUARD_SIZE: usize = 16 << 20;

/// A memfd-backed pool of guest pages.
pub struct BackingStore {
    /// File descriptor from `memfd_create`.
    fd: i32,
}

impl BackingStore {
    /// Create a new backing store with `total_pages` of capacity.
    ///
    /// Calls `memfd_create` + `ftruncate`. Physical pages are allocated
    /// lazily by the kernel on first write. `None` where the host refuses
    /// it: a file-size limit below the size is checked first, since past it
    /// `ftruncate` raises `SIGXFSZ`, which ends the process.
    pub fn new(total_pages: u32) -> Option<Self> {
        let size = total_pages as libc::off_t * PVM_PAGE_SIZE as libc::off_t;
        // SAFETY: getrlimit writes the limit into a valid struct.
        let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrlimit(libc::RLIMIT_FSIZE, &mut limit) } != 0
            || (limit.rlim_cur != libc::RLIM_INFINITY && limit.rlim_cur < size as libc::rlim_t)
        {
            return None;
        }
        let name = b"pvm_untyped\0";
        // Set close-on-exec atomically: another thread may launch a process
        // while an invocation is constructing its temporary shared mapping.
        // Guest memory is never executable: seal it so (which a host with
        // `vm.memfd_noexec = 2` requires); a kernel before 6.3 knows no such
        // flag and refuses it.
        let create = |flags| {
            // SAFETY: memfd_create with a valid null-terminated name and flags.
            unsafe { libc::memfd_create(name.as_ptr() as *const libc::c_char, flags) }
        };
        let mut fd = create(libc::MFD_CLOEXEC | libc::MFD_NOEXEC_SEAL);
        if fd < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
            fd = create(libc::MFD_CLOEXEC);
        }
        if fd < 0 {
            return None;
        }
        // SAFETY: fd is valid from memfd_create; size is non-negative.
        let ret = unsafe { libc::ftruncate(fd, size) };
        if ret < 0 {
            // SAFETY: fd is valid.
            unsafe { libc::close(fd) };
            return None;
        }
        Some(Self { fd })
    }

    /// The raw file descriptor (for mmap calls).
    pub fn fd(&self) -> i32 {
        self.fd
    }
}

impl Drop for BackingStore {
    fn drop(&mut self) {
        // SAFETY: fd is valid from memfd_create in new().
        unsafe { libc::close(self.fd) };
    }
}

// ─── CodeWindow ───────────────────────────────────────────────────────────

/// The JIT's virtual address space window.
///
/// One reservation: the permission table and the context, then guest
/// memory between two inaccessible guards.
///
/// Layout:
/// ```text
/// [permissions (1MiB)] [CTX (4KiB)] [low guard] [guest memory (4GiB)] [guard]
/// ^                     ^                        ^
/// perms()               ctx_ptr()                base()  ← R15 in JIT code
/// ```
pub struct CodeWindow {
    /// Base of the entire mmap'd region (the permission table).
    region: *mut u8,
    /// Total region size including metadata and both guards.
    region_size: usize,
    /// Guest memory base (region + header). This is R15 in JIT code.
    base: *mut u8,
}

impl CodeWindow {
    /// Reserve a new window: the permission table and context writable,
    /// everything else inaccessible until guest memory is mapped.
    pub fn new() -> Option<Self> {
        let region_size = CODE_WINDOW_HEADER_SIZE + CODE_WINDOW_SIZE + CODE_WINDOW_GUARD_SIZE;
        // SAFETY: MAP_ANONYMOUS | MAP_NORESERVE allocates virtual address space only.
        let region = unsafe {
            libc::mmap(
                std::ptr::null_mut(),
                region_size,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            )
        };
        if region == libc::MAP_FAILED {
            return None;
        }
        let region = region as *mut u8;

        // SAFETY: the table and context lie wholly within the fresh mapping.
        unsafe {
            if libc::mprotect(
                region as *mut libc::c_void,
                CODE_WINDOW_PERMS_SIZE + CODE_WINDOW_CTX_SIZE,
                libc::PROT_READ | libc::PROT_WRITE,
            ) != 0
            {
                libc::munmap(region as *mut libc::c_void, region_size);
                return None;
            }
        }

        // SAFETY: the header is strictly smaller than the complete mapping.
        let base = unsafe { region.add(CODE_WINDOW_HEADER_SIZE) };

        Some(Self {
            region,
            region_size,
            base,
        })
    }

    /// Guest memory base pointer (R15 in JIT code).
    pub fn base(&self) -> *mut u8 {
        self.base
    }

    /// Pointer to the JitContext page, below the low guard.
    pub fn ctx_ptr(&self) -> *mut u8 {
        // SAFETY: the context page directly follows the permission table.
        unsafe { self.region.add(CODE_WINDOW_PERMS_SIZE) }
    }

    /// Pointer to the page-permission table (one byte per guest page).
    pub fn perms(&self) -> *mut u8 {
        self.region
    }
}

impl Drop for CodeWindow {
    fn drop(&mut self) {
        // SAFETY: region/region_size from mmap in new().
        unsafe { libc::munmap(self.region as *mut libc::c_void, self.region_size) };
    }
}

// SAFETY: the window owns its mapping, unmapped once on drop, and its
// methods only hand out pointers into it: every access through them is an
// unsafe caller's, under that caller's own argument.
unsafe impl Send for CodeWindow {}
// SAFETY: as for `Send`: `&CodeWindow` reads no memory behind its pointers.
unsafe impl Sync for CodeWindow {}

// ─── Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backing_descriptor_is_close_on_exec_before_it_can_escape() {
        let store = BackingStore::new(1).unwrap();
        // SAFETY: the live store owns this valid descriptor; F_GETFD is read-only.
        let flags = unsafe { libc::fcntl(store.fd(), libc::F_GETFD) };
        assert!(flags >= 0);
        assert_ne!(
            flags & libc::FD_CLOEXEC,
            0,
            "a concurrently launched process must not inherit invocation memory"
        );
    }

    /// Whether `address` can be read, asked of the kernel: a write from
    /// it into a pipe fails with `EFAULT` where it is inaccessible.
    fn readable(address: *const u8) -> bool {
        let mut pipe = [0; 2];
        // SAFETY: pipe fills a valid two-descriptor array; write reads one
        // byte at `address` in the kernel, which never faults the process.
        unsafe {
            assert_eq!(libc::pipe(pipe.as_mut_ptr()), 0);
            let wrote = libc::write(pipe[1], address.cast(), 1);
            libc::close(pipe[0]);
            libc::close(pipe[1]);
            wrote == 1
        }
    }

    /// The pages on both sides of the guest window are inaccessible, and
    /// the context, which redirects control, is past the low guard.
    #[test]
    fn the_guest_window_is_guarded_on_both_sides() {
        let window = CodeWindow::new().expect("CodeWindow::new failed");
        let base = window.base() as usize;
        let ctx = window.ctx_ptr() as usize;
        assert!(readable(window.ctx_ptr()));
        assert!(readable(window.perms()));
        assert!(base - (ctx + CODE_WINDOW_CTX_SIZE) >= CODE_WINDOW_LOW_GUARD_SIZE);
        let table = window.perms() as usize;
        assert!(
            ctx >= table + CODE_WINDOW_PERMS_SIZE,
            "the table is below the context"
        );
        for address in [
            ctx + CODE_WINDOW_CTX_SIZE,
            base - CODE_WINDOW_LOW_GUARD_SIZE,
            base - 1,
            base,
            base + CODE_WINDOW_SIZE,
            base + CODE_WINDOW_SIZE + CODE_WINDOW_GUARD_SIZE - 1,
        ] {
            assert!(
                !readable(address as *const u8),
                "{:#x} past base",
                address.wrapping_sub(base)
            );
        }
    }
}
