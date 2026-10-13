//! Dirty-page tracking options for native execution.
//!
//! Each option runs on a JIT-like window: 4 GiB of reserved address space
//! with a memfd mapped shared over it, a writable region and a second host
//! alias of the same file.
//!
//! - `baseline`: stores into populated, untracked pages.
//! - `(a) mprotect`: the region is read-only; a SIGSEGV handler records the
//!   page and makes it writable; capture re-protects the region.
//! - `(c) uffd`: userfaultfd write-protect in async mode; capture is one
//!   `PAGEMAP_SCAN` that reports written pages and re-protects them.
//!
//! For k written pages it reports the store cost (the first write to each
//! page after a capture) and the capture cost, as medians.

use std::time::{Duration, Instant};

const PAGE: usize = 4096;
const SPAN: usize = 1 << 32;
/// Writable region: 8 MiB in the middle of the window.
const REGION: usize = 0x4000_0000;
const REGION_PAGES: usize = 2048;
const SAMPLES: usize = 101;

const UFFD_USER_MODE_ONLY: libc::c_int = 1;
const UFFD_API: u64 = 0xaa;
const UFFD_FEATURE_WP_HUGETLBFS_SHMEM: u64 = 1 << 12;
const UFFD_FEATURE_WP_UNPOPULATED: u64 = 1 << 13;
const UFFD_FEATURE_WP_ASYNC: u64 = 1 << 15;
const UFFDIO_API: libc::c_ulong = 0xc018_aa3f;
const UFFDIO_REGISTER: libc::c_ulong = 0xc020_aa00;
const UFFDIO_REGISTER_MODE_WP: u64 = 1 << 1;
const UFFDIO_WRITEPROTECT: libc::c_ulong = 0xc018_aa06;
const UFFDIO_WRITEPROTECT_MODE_WP: u64 = 1;
const PAGEMAP_SCAN: libc::c_ulong = 0xc060_6610;
const PM_SCAN_WP_MATCHING: u64 = 1;
const PM_SCAN_CHECK_WPASYNC: u64 = 1 << 1;
const PAGE_IS_WRITTEN: u64 = 1 << 1;

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

/// A JIT-like window over a memfd, plus the host alias.
struct Window {
    base: *mut u8,
    host: *mut u8,
}

impl Window {
    fn new() -> Self {
        // SAFETY: plain mmap/memfd calls; every result is checked.
        unsafe {
            let fd = libc::memfd_create(c"dirty-bench".as_ptr(), libc::MFD_CLOEXEC);
            assert!(fd >= 0);
            assert_eq!(libc::ftruncate(fd, SPAN as i64), 0);
            let reserve = libc::mmap(
                std::ptr::null_mut(),
                SPAN,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_NORESERVE,
                -1,
                0,
            );
            assert_ne!(reserve, libc::MAP_FAILED);
            let base = libc::mmap(
                reserve,
                SPAN,
                libc::PROT_NONE,
                libc::MAP_SHARED | libc::MAP_FIXED,
                fd,
                0,
            );
            assert_ne!(base, libc::MAP_FAILED);
            let host = libc::mmap(
                std::ptr::null_mut(),
                SPAN,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                fd,
                0,
            );
            assert_ne!(host, libc::MAP_FAILED);
            libc::close(fd);
            // As the runtime does: page-granular tracking needs 4 KiB pages.
            libc::madvise(base, SPAN, libc::MADV_NOHUGEPAGE);
            libc::madvise(host, SPAN, libc::MADV_NOHUGEPAGE);
            let window = Self {
                base: base.cast(),
                host: host.cast(),
            };
            window.protect(libc::PROT_READ | libc::PROT_WRITE);
            window
        }
    }

    fn region(&self) -> *mut u8 {
        // SAFETY: REGION lies inside the window.
        unsafe { self.base.add(REGION) }
    }

    fn protect(&self, protection: libc::c_int) {
        // SAFETY: the region belongs to this window.
        assert_eq!(
            unsafe { libc::mprotect(self.region().cast(), REGION_PAGES * PAGE, protection) },
            0
        );
    }

    /// One store into each of the first `k` pages of the region.
    fn touch(&self, k: usize, value: u8) {
        for page in 0..k {
            // SAFETY: inside the writable region.
            unsafe { std::ptr::write_volatile(self.region().add(page * PAGE + 8), value) };
        }
    }

    /// Discard the region's backing pages through the host alias.
    fn punch(&self) {
        // SAFETY: the host alias covers the region.
        assert_eq!(
            unsafe {
                libc::madvise(
                    self.host.add(REGION).cast(),
                    REGION_PAGES * PAGE,
                    libc::MADV_REMOVE,
                )
            },
            0
        );
    }
}

/// Userfaultfd write-protect tracking over a window's region.
struct Uffd {
    fd: libc::c_int,
    pagemap: libc::c_int,
    regions: Vec<PageRegion>,
}

impl Uffd {
    fn new(window: &Window) -> Result<Self, String> {
        // SAFETY: syscalls with checked results; the structs match the
        // kernel's uapi layouts.
        unsafe {
            let fd = libc::syscall(
                libc::SYS_userfaultfd,
                libc::O_CLOEXEC | libc::O_NONBLOCK | UFFD_USER_MODE_ONLY,
            ) as libc::c_int;
            if fd < 0 {
                return Err(format!("userfaultfd: {}", std::io::Error::last_os_error()));
            }
            let wanted = UFFD_FEATURE_WP_ASYNC
                | UFFD_FEATURE_WP_HUGETLBFS_SHMEM
                | UFFD_FEATURE_WP_UNPOPULATED;
            let mut api = UffdioApi {
                api: UFFD_API,
                features: wanted,
                ioctls: 0,
            };
            if libc::ioctl(fd, UFFDIO_API, &mut api) != 0 {
                return Err(format!("UFFDIO_API: {}", std::io::Error::last_os_error()));
            }
            let mut register = UffdioRegister {
                range: UffdioRange {
                    start: window.base as u64,
                    len: SPAN as u64,
                },
                mode: UFFDIO_REGISTER_MODE_WP,
                ioctls: 0,
            };
            if libc::ioctl(fd, UFFDIO_REGISTER, &mut register) != 0 {
                return Err(format!(
                    "UFFDIO_REGISTER: {}",
                    std::io::Error::last_os_error()
                ));
            }
            let pagemap = libc::open(c"/proc/self/pagemap".as_ptr(), libc::O_RDONLY);
            assert!(pagemap >= 0);
            let tracker = Self {
                fd,
                pagemap,
                regions: vec![PageRegion::default(); 64],
            };
            tracker.write_protect(window, REGION, REGION_PAGES * PAGE);
            Ok(tracker)
        }
    }

    fn write_protect(&self, window: &Window, offset: usize, len: usize) {
        let mut protect = UffdioWriteprotect {
            range: UffdioRange {
                start: window.base as u64 + offset as u64,
                len: len as u64,
            },
            mode: UFFDIO_WRITEPROTECT_MODE_WP,
        };
        // SAFETY: the range was registered above.
        let result = unsafe { libc::ioctl(self.fd, UFFDIO_WRITEPROTECT, &mut protect) };
        assert_eq!(result, 0, "{}", std::io::Error::last_os_error());
    }

    /// Report the written pages in `[offset, offset + len)` of the window
    /// and write-protect them again.
    fn capture_range(&mut self, window: &Window, offset: usize, len: usize) -> usize {
        let mut arg = PmScanArg {
            size: std::mem::size_of::<PmScanArg>() as u64,
            flags: PM_SCAN_WP_MATCHING | PM_SCAN_CHECK_WPASYNC,
            start: window.base as u64 + offset as u64,
            end: window.base as u64 + (offset + len) as u64,
            walk_end: 0,
            vec: self.regions.as_mut_ptr() as u64,
            vec_len: self.regions.len() as u64,
            max_pages: 0,
            category_inverted: 0,
            category_mask: PAGE_IS_WRITTEN,
            category_anyof_mask: 0,
            return_mask: PAGE_IS_WRITTEN,
        };
        // SAFETY: arg points at a correctly sized output vector.
        let found = unsafe { libc::ioctl(self.pagemap, PAGEMAP_SCAN, &mut arg) };
        assert!(
            found >= 0,
            "PAGEMAP_SCAN: {}",
            std::io::Error::last_os_error()
        );
        assert_eq!(arg.walk_end, arg.end, "scan stopped early");
        self.regions[..found as usize]
            .iter()
            .map(|region| ((region.end - region.start) / PAGE as u64) as usize)
            .sum()
    }

    /// Capture over the writable region only.
    fn capture(&mut self, window: &Window) -> usize {
        self.capture_range(window, REGION, REGION_PAGES * PAGE)
    }
}

thread_local! {
    static FAULTS: std::cell::RefCell<Vec<usize>> = const { std::cell::RefCell::new(Vec::new()) };
}

extern "C" fn on_write_fault(_: libc::c_int, info: *mut libc::siginfo_t, _: *mut libc::c_void) {
    // SAFETY: SA_SIGINFO delivers a valid siginfo for SIGSEGV.
    let address = unsafe { (*info).si_addr() } as usize & !(PAGE - 1);
    FAULTS.with(|faults| faults.borrow_mut().push(address));
    // SAFETY: the faulting page lies in the bench's writable region.
    unsafe {
        libc::mprotect(
            address as *mut libc::c_void,
            PAGE,
            libc::PROT_READ | libc::PROT_WRITE,
        )
    };
}

fn install_handler() {
    // SAFETY: installs a SIGSEGV handler for this bench process.
    unsafe {
        let mut action: libc::sigaction = std::mem::zeroed();
        action.sa_sigaction = on_write_fault as usize;
        action.sa_flags = libc::SA_SIGINFO;
        assert_eq!(
            libc::sigaction(libc::SIGSEGV, &action, std::ptr::null_mut()),
            0
        );
    }
}

fn median(mut samples: Vec<Duration>) -> f64 {
    samples.sort();
    samples[samples.len() / 2].as_secs_f64() * 1e6
}

fn main() {
    let ks = [1usize, 3, 10, 100, REGION_PAGES];
    println!(
        "{:>16} {:>6} {:>12} {:>12} {:>12}",
        "option", "pages", "stores µs", "µs/page", "capture µs"
    );

    let window = Window::new();
    let started = Instant::now();
    window.touch(REGION_PAGES, 1);
    let first = started.elapsed().as_secs_f64() * 1e6;
    println!(
        "{:>16} {:>6} {:>12.2} {:>12.3} {:>12}",
        "base first touch",
        REGION_PAGES,
        first,
        first / REGION_PAGES as f64,
        "-"
    );
    for &k in &ks {
        let stores: Vec<_> = (0..SAMPLES)
            .map(|round| {
                let started = Instant::now();
                window.touch(k, round as u8);
                started.elapsed()
            })
            .collect();
        let stores = median(stores);
        println!(
            "{:>16} {:>6} {:>12.2} {:>12.3} {:>12}",
            "baseline",
            k,
            stores,
            stores / k as f64,
            "-"
        );
    }

    install_handler();
    let window = Window::new();
    window.touch(REGION_PAGES, 1);
    for &k in &ks {
        let (stores, captures): (Vec<_>, Vec<_>) = (0..SAMPLES)
            .map(|round| {
                window.protect(libc::PROT_READ);
                FAULTS.with(|faults| faults.borrow_mut().clear());
                let started = Instant::now();
                window.touch(k, round as u8);
                let stores = started.elapsed();
                let started = Instant::now();
                let pages = FAULTS.with(|faults| std::mem::take(&mut *faults.borrow_mut()));
                window.protect(libc::PROT_READ);
                let capture = started.elapsed();
                assert_eq!(pages.len(), k);
                (stores, capture)
            })
            .unzip();
        let stores = median(stores);
        println!(
            "{:>16} {:>6} {:>12.2} {:>12.3} {:>12.2}",
            "(a) mprotect",
            k,
            stores,
            stores / k as f64,
            median(captures)
        );
    }

    let window = Window::new();
    let mut uffd = match Uffd::new(&window) {
        Ok(uffd) => uffd,
        Err(error) => {
            println!("(c) unavailable: {error}");
            return;
        }
    };
    // First touch of never-populated pages, protected while unpopulated.
    let started = Instant::now();
    window.touch(REGION_PAGES, 1);
    let first = started.elapsed().as_secs_f64() * 1e6;
    assert_eq!(uffd.capture(&window), REGION_PAGES, "unpopulated writes");
    println!(
        "{:>16} {:>6} {:>12.2} {:>12.3} {:>12}",
        "(c) first touch",
        REGION_PAGES,
        first,
        first / REGION_PAGES as f64,
        "-"
    );
    for &k in &ks {
        let (stores, captures): (Vec<_>, Vec<_>) = (0..SAMPLES)
            .map(|round| {
                let started = Instant::now();
                window.touch(k, round as u8);
                let stores = started.elapsed();
                let started = Instant::now();
                let pages = uffd.capture(&window);
                let capture = started.elapsed();
                assert_eq!(pages, k);
                (stores, capture)
            })
            .unzip();
        let stores = median(stores);
        println!(
            "{:>16} {:>6} {:>12.2} {:>12.3} {:>12.2}",
            "(c) uffd",
            k,
            stores,
            stores / k as f64,
            median(captures)
        );
    }

    // Capture over a protected range whose pages were never populated,
    // as on a fresh machine whose heap is mostly untouched: the scan walks
    // one write-protect marker per page.
    for mib in [8usize, 64, 512] {
        let pages = mib << 8;
        let fresh = Window::new();
        let mut register = UffdioRegister {
            range: UffdioRange {
                start: fresh.base as u64,
                len: SPAN as u64,
            },
            mode: UFFDIO_REGISTER_MODE_WP,
            ioctls: 0,
        };
        // SAFETY: the fresh window is a live mapping.
        assert_eq!(
            unsafe { libc::ioctl(uffd.fd, UFFDIO_REGISTER, &mut register) },
            0
        );
        // SAFETY: the range lies inside the fresh window.
        assert_eq!(
            unsafe {
                libc::mprotect(
                    fresh.region().cast(),
                    pages * PAGE,
                    libc::PROT_READ | libc::PROT_WRITE,
                )
            },
            0
        );
        uffd.write_protect(&fresh, REGION, pages * PAGE);
        let captures: Vec<_> = (0..SAMPLES)
            .map(|round| {
                fresh.touch(3, round as u8);
                let started = Instant::now();
                assert_eq!(uffd.capture_range(&fresh, REGION, pages * PAGE), 3);
                started.elapsed()
            })
            .collect();
        println!(
            "{:>16} {:>6} {:>12} {:>12} {:>12.2}",
            format!("(c) {mib} MiB"),
            3,
            "-",
            "-",
            median(captures)
        );
    }

    // Cost of write-protecting a fresh, unpopulated range.
    for pages in [16usize, 1024, REGION_PAGES] {
        let protects: Vec<_> = (0..21)
            .map(|_| {
                let fresh = Window::new();
                let tracker = Uffd {
                    fd: uffd.fd,
                    pagemap: uffd.pagemap,
                    regions: Vec::new(),
                };
                let mut register = UffdioRegister {
                    range: UffdioRange {
                        start: fresh.base as u64,
                        len: SPAN as u64,
                    },
                    mode: UFFDIO_REGISTER_MODE_WP,
                    ioctls: 0,
                };
                // SAFETY: the fresh window is a live mapping.
                assert_eq!(
                    unsafe { libc::ioctl(uffd.fd, UFFDIO_REGISTER, &mut register) },
                    0
                );
                let started = Instant::now();
                tracker.write_protect(&fresh, REGION, pages * PAGE);
                started.elapsed()
            })
            .collect();
        println!(
            "{:>16} {:>6} {:>12} {:>12} {:>12.2}",
            "(c) protect",
            pages,
            "-",
            "-",
            median(protects)
        );
    }

    // Pages never write-protected report as written, so a capture must
    // scan exactly the ranges it protected.
    assert!(uffd.capture_range(&window, 0, PAGE) == 1);

    // Tracking must survive the window's own permission changes and the
    // host discarding pages.
    window.protect(libc::PROT_READ);
    window.protect(libc::PROT_READ | libc::PROT_WRITE);
    window.touch(3, 9);
    assert_eq!(uffd.capture(&window), 3, "writes after mprotect");
    window.punch();
    window.touch(3, 9);
    assert_eq!(uffd.capture(&window), 3, "writes after MADV_REMOVE");
    assert_eq!(uffd.capture(&window), 0, "capture re-protects");
    // Host-alias writes are not guest writes.
    // SAFETY: the host alias covers the region.
    unsafe { std::ptr::write_volatile(window.host.add(REGION), 5) };
    assert_eq!(uffd.capture(&window), 0, "host alias is untracked");
    println!("(c) checks: mprotect, MADV_REMOVE and host-alias writes behave");
}
