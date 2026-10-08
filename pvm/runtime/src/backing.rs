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
/// Writable page containing the native JIT context immediately before RAM.
pub const CODE_WINDOW_CTX_SIZE: usize = 4096;
/// Metadata prefix before guest memory.
pub const CODE_WINDOW_HEADER_SIZE: usize = CODE_WINDOW_PERMS_SIZE + CODE_WINDOW_CTX_SIZE;
/// Inaccessible native page after the 32-bit guest address space.
pub const CODE_WINDOW_GUARD_SIZE: usize = 4096;

/// A memfd-backed pool of guest pages.
pub struct BackingStore {
    /// File descriptor from `memfd_create`.
    fd: i32,
}

impl BackingStore {
    /// Create a new backing store with `total_pages` of capacity.
    ///
    /// Calls `memfd_create` + `ftruncate`. Physical pages are allocated
    /// lazily by the kernel on first write.
    pub fn new(total_pages: u32) -> Option<Self> {
        let name = b"pvm_untyped\0";
        // Set close-on-exec atomically: another thread may launch a process
        // while an invocation is constructing its temporary shared mapping.
        // SAFETY: memfd_create with a valid null-terminated name and flags.
        let fd =
            unsafe { libc::memfd_create(name.as_ptr() as *const libc::c_char, libc::MFD_CLOEXEC) };
        if fd < 0 {
            return None;
        }
        let size = total_pages as libc::off_t * PVM_PAGE_SIZE as libc::off_t;
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
/// A full 4GB mmap region with a permission-table and CTX prefix plus an
/// inaccessible trailing guard page.
///
/// Layout:
/// ```text
/// [permissions (1MiB)] [CTX (4KiB)] [guest memory] [guard]
/// ^                     ^           ^
/// perms()               ctx_ptr()   base()  ← R15 in JIT code
/// ```
pub struct CodeWindow {
    /// Base of the entire mmap'd region (CTX page).
    region: *mut u8,
    /// Total region size including metadata and the trailing guard.
    region_size: usize,
    /// Guest memory base (region + CTX_PAGE). This is R15 in JIT code.
    base: *mut u8,
}

impl CodeWindow {
    /// Allocate a new 4GB window with CTX page.
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

        // Make the permission table and CTX page writable. Guest RAM and the
        // trailing guard remain PROT_NONE until guest memory is mapped.
        // SAFETY: the header lies wholly within the fresh mapping.
        unsafe {
            if libc::mprotect(
                region as *mut libc::c_void,
                CODE_WINDOW_HEADER_SIZE,
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

    /// Pointer to the JitContext page (base - CTX_PAGE).
    pub fn ctx_ptr(&self) -> *mut u8 {
        // SAFETY: base follows the complete header and the CTX is its final page.
        unsafe { self.base.sub(CODE_WINDOW_CTX_SIZE) }
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

unsafe impl Send for CodeWindow {}
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

    #[test]
    fn test_code_window_create() {
        let window = CodeWindow::new().expect("CodeWindow::new failed");
        assert!(!window.base().is_null());
    }
}
