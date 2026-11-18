//! Guest-write tracking for native windows: userfaultfd write-protect in
//! asynchronous mode, collected with `PAGEMAP_SCAN`.
//!
//! A write-protected page takes one in-kernel fault on its first write,
//! which clears the protection; no signal reaches the process and later
//! stores cost nothing. A capture is one ioctl per range: it reports the
//! pages written since the last capture and protects them again.
//!
//! Pages that were never write-protected report as written, so captures
//! scan exactly the ranges that were protected. Requires Linux 6.7 or later
//! (`UFFD_FEATURE_WP_ASYNC` and `PAGEMAP_SCAN`); `UFFD_USER_MODE_ONLY` lets
//! an unprivileged process open the descriptor.

use std::sync::OnceLock;

const UFFD_USER_MODE_ONLY: libc::c_int = 1;
const UFFD_API: u64 = 0xaa;
const UFFD_FEATURE_WP_HUGETLBFS_SHMEM: u64 = 1 << 12;
const UFFD_FEATURE_WP_ASYNC: u64 = 1 << 15;
// An ioctl's request is a C `unsigned long` under glibc and an `int` under
// musl: each request's 32 bits, as the target's libc takes them.
const UFFDIO_API: libc::Ioctl = 0xc018_aa3f_u32 as libc::Ioctl;
const UFFDIO_REGISTER: libc::Ioctl = 0xc020_aa00_u32 as libc::Ioctl;
const UFFDIO_REGISTER_MODE_WP: u64 = 1 << 1;
const UFFDIO_WRITEPROTECT: libc::Ioctl = 0xc018_aa06_u32 as libc::Ioctl;
const UFFDIO_WRITEPROTECT_MODE_WP: u64 = 1;
const PAGEMAP_SCAN: libc::Ioctl = 0xc060_6610_u32 as libc::Ioctl;
const PM_SCAN_WP_MATCHING: u64 = 1;
const PM_SCAN_CHECK_WPASYNC: u64 = 1 << 1;
const PAGE_IS_WRITTEN: u64 = 1 << 1;
const PAGE: u64 = 4096;

#[repr(C)]
struct UffdioApi {
    api: u64,
    features: u64,
    ioctls: u64,
}

#[repr(C)]
struct UffdioRange {
    start: u64,
    len: u64,
}

#[repr(C)]
struct UffdioRegister {
    range: UffdioRange,
    mode: u64,
    ioctls: u64,
}

#[repr(C)]
struct UffdioWriteprotect {
    range: UffdioRange,
    mode: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
struct PageRegion {
    start: u64,
    end: u64,
    categories: u64,
}

#[repr(C)]
struct PmScanArg {
    size: u64,
    flags: u64,
    start: u64,
    end: u64,
    walk_end: u64,
    vec: u64,
    vec_len: u64,
    max_pages: u64,
    category_inverted: u64,
    category_mask: u64,
    category_anyof_mask: u64,
    return_mask: u64,
}

/// The process-wide descriptors: one userfaultfd serves every window, and
/// captures read the process's own pagemap.
struct Descriptors {
    uffd: libc::c_int,
    pagemap: libc::c_int,
}

static DESCRIPTORS: OnceLock<Result<Descriptors, String>> = OnceLock::new();

fn descriptors() -> Result<&'static Descriptors, String> {
    DESCRIPTORS.get_or_init(open).as_ref().map_err(Clone::clone)
}

fn open() -> Result<Descriptors, String> {
    let error = |what: &str| format!("{what}: {}", std::io::Error::last_os_error());
    // SAFETY: syscalls with checked results; the structs match the kernel's
    // uapi layouts. The descriptors live for the rest of the process.
    unsafe {
        let uffd = libc::syscall(
            libc::SYS_userfaultfd,
            libc::O_CLOEXEC | libc::O_NONBLOCK | UFFD_USER_MODE_ONLY,
        ) as libc::c_int;
        if uffd < 0 {
            return Err(error("userfaultfd"));
        }
        let features = UFFD_FEATURE_WP_ASYNC | UFFD_FEATURE_WP_HUGETLBFS_SHMEM;
        let mut api = UffdioApi {
            api: UFFD_API,
            features,
            ioctls: 0,
        };
        if libc::ioctl(uffd, UFFDIO_API, &mut api) != 0 || api.features & features != features {
            libc::close(uffd);
            return Err(error("userfaultfd asynchronous write-protect"));
        }
        let pagemap = libc::open(
            c"/proc/self/pagemap".as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC,
        );
        if pagemap < 0 {
            libc::close(uffd);
            return Err(error("/proc/self/pagemap"));
        }
        Ok(Descriptors { uffd, pagemap })
    }
}

/// Whether this host can track native guest writes.
pub(crate) fn available() -> bool {
    descriptors().is_ok()
}

/// Register a mapped window range for write tracking. Nothing is protected
/// until [`protect`].
pub(crate) fn register(base: *mut u8, len: usize) -> Result<(), String> {
    let descriptors = descriptors()?;
    let mut register = UffdioRegister {
        range: UffdioRange {
            start: base as u64,
            len: len as u64,
        },
        mode: UFFDIO_REGISTER_MODE_WP,
        ioctls: 0,
    };
    // SAFETY: the range is a live mapping owned by the caller.
    if unsafe { libc::ioctl(descriptors.uffd, UFFDIO_REGISTER, &mut register) } != 0 {
        return Err(format!(
            "userfaultfd register: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Write-protect a registered range, so its next writes are reported.
pub(crate) fn protect(base: *mut u8, len: usize) -> Result<(), String> {
    let descriptors = descriptors()?;
    let mut protect = UffdioWriteprotect {
        range: UffdioRange {
            start: base as u64,
            len: len as u64,
        },
        mode: UFFDIO_WRITEPROTECT_MODE_WP,
    };
    // SAFETY: the range was registered by its owner.
    if unsafe { libc::ioctl(descriptors.uffd, UFFDIO_WRITEPROTECT, &mut protect) } != 0 {
        return Err(format!(
            "userfaultfd write-protect: {}",
            std::io::Error::last_os_error()
        ));
    }
    Ok(())
}

/// Write-protect a registered range from the fault handler: no allocation
/// and no initialization, since a window is registered before it runs.
pub(crate) fn protect_in_handler(base: *mut u8, len: usize) -> bool {
    let Some(Ok(descriptors)) = DESCRIPTORS.get() else {
        return false;
    };
    let mut protect = UffdioWriteprotect {
        range: UffdioRange {
            start: base as u64,
            len: len as u64,
        },
        mode: UFFDIO_WRITEPROTECT_MODE_WP,
    };
    // SAFETY: the range was registered by its owner; ioctl is
    // async-signal-safe.
    unsafe { libc::ioctl(descriptors.uffd, UFFDIO_WRITEPROTECT, &mut protect) == 0 }
}

/// Visit the runs of pages written in a protected range since the last
/// capture, as (byte offset from `base`, length), and protect them again.
pub(crate) fn capture(
    base: *mut u8,
    len: usize,
    mut visit: impl FnMut(usize, usize),
) -> Result<(), String> {
    let descriptors = descriptors()?;
    let mut regions = [PageRegion::default(); 32];
    let end = base as u64 + len as u64;
    let mut start = base as u64;
    while start < end {
        let mut arg = PmScanArg {
            size: core::mem::size_of::<PmScanArg>() as u64,
            flags: PM_SCAN_WP_MATCHING | PM_SCAN_CHECK_WPASYNC,
            start,
            end,
            walk_end: 0,
            vec: regions.as_mut_ptr() as u64,
            vec_len: regions.len() as u64,
            max_pages: 0,
            category_inverted: 0,
            category_mask: PAGE_IS_WRITTEN,
            category_anyof_mask: 0,
            return_mask: PAGE_IS_WRITTEN,
        };
        // SAFETY: `arg` describes a correctly sized output vector, and the
        // range is a protected mapping owned by the caller.
        let found = unsafe { libc::ioctl(descriptors.pagemap, PAGEMAP_SCAN, &mut arg) };
        if found < 0 || arg.walk_end <= start || arg.walk_end > end {
            return Err(format!("pagemap scan: {}", std::io::Error::last_os_error()));
        }
        for region in &regions[..found as usize] {
            debug_assert!(region.start.is_multiple_of(PAGE) && region.end.is_multiple_of(PAGE));
            visit(
                (region.start - base as u64) as usize,
                (region.end - region.start) as usize,
            );
        }
        start = arg.walk_end;
    }
    Ok(())
}
