//! Two views of one invocation's memory: checked host access and protected JIT access.
//!
//! Both aliases share lazily allocated pages. Native execution never sees the
//! unprotected host alias, and host reads/clears retain `Memory`'s semantics even
//! for pages which are inaccessible to the guest. Neither alias owns a dense
//! allocation or a live file descriptor after construction.
//!
//! Guest stores through the window are tracked by write-protecting exactly
//! the guest-writable pages ([`super::write_tracking`]); host writes through
//! the other alias are recorded by `Memory` itself.
//!
//! Tracking starts per permission slot at the guest's first write into it.
//! Until then the slot's writable pages are mapped read-only; the first
//! write faults, and the fault handler write-protects the slot's writable
//! runs for tracking, makes them writable and retries the store
//! ([`Activation`]). Protection and captures therefore cost in proportion to
//! the slots the guest writes, never to how much it maps. A slot with few
//! writable pages, such as a small actor's stack, starts tracking as soon as
//! they are mapped, since that is cheaper than its first fault.

use core::sync::atomic::{AtomicBool, Ordering};

use crate::backing::{BackingStore, CodeWindow};
use crate::interpreter::PERM_RW;
use crate::interpreter::memory::{PagePerms, SLOT_PAGES, SlotPerms};

/// A slot with at most this many writable pages tracks writes from the
/// moment they are mapped.
const EAGER_PAGES: usize = 64;

pub(crate) struct NativeMemory {
    host: *mut u8,
    span: usize,
    window: CodeWindow,
    /// Per permission slot: the permission installed on every page of the
    /// slot, or `None` when the window's table holds mixed entries. Lets a
    /// changed slot that is uniform again skip its table and mprotect.
    applied: Vec<Option<u8>>,
    /// Whether a permission map has been applied to this window. The first
    /// sync applies every slot, whatever the map's changed bits say.
    synced: bool,
    /// Per permission slot, the guest-writable runs (first page, count) as
    /// installed in the window. Each page is write-protected for tracking
    /// before it becomes writable, and captures scan exactly these runs.
    writable: alloc::collections::BTreeMap<usize, Vec<(usize, usize)>>,
    /// Runs written by the guest that have since stopped being writable,
    /// collected when they left and reported by the next capture.
    left: Vec<(usize, usize)>,
    /// Slot activation, shared with the fault handler.
    activation: alloc::boxed::Box<Activation>,
}

/// Which slots track guest writes, and what the fault handler needs to
/// start tracking one.
pub(crate) struct Activation {
    base: *mut u8,
    perms: *const u8,
    pages: usize,
    active: alloc::boxed::Box<[AtomicBool]>,
    /// Set when tracking failed or the window's protection disagreed with
    /// it. From then on every capture reports the whole span.
    failed: AtomicBool,
}

/// What a write fault meant to [`Activation::activate`].
pub(crate) enum Activated {
    /// The slot now tracks writes; retry the store.
    Started,
    /// Not a tracking fault: a guest page fault.
    NotTracking,
    /// Tracking failed, or a tracking slot faulted on a writable page;
    /// native execution cannot continue.
    Failed,
}

impl Activation {
    fn is_active(&self, slot: usize) -> bool {
        self.active[slot].load(Ordering::Relaxed)
    }

    /// Handle a guest write fault on `page`. Called from the fault handler,
    /// so it performs only system calls on preallocated state.
    pub(crate) fn activate(&self, page: usize) -> Activated {
        if page >= self.pages {
            return Activated::NotTracking;
        }
        // SAFETY: the window's permission table covers every guest page.
        if unsafe { *self.perms.add(page) } != PERM_RW {
            return Activated::NotTracking;
        }
        // A tracking slot maps its writable pages writable, so a write fault
        // there means the window and the tracking state disagree.
        if self.is_active(page / SLOT_PAGES) || !self.start(page / SLOT_PAGES) {
            self.failed.store(true, Ordering::Relaxed);
            return Activated::Failed;
        }
        Activated::Started
    }

    /// Start tracking writes in `slot`: write-protect its writable runs as
    /// the window's table records them, then make them writable. Performs
    /// only system calls, so the fault handler may call it.
    fn start(&self, slot: usize) -> bool {
        let first = slot * SLOT_PAGES;
        let len = (first + SLOT_PAGES).min(self.pages) - first;
        // SAFETY: as above, for the slot's pages.
        let perms = unsafe { core::slice::from_raw_parts(self.perms.add(first), len) };
        let mut at = 0;
        while at < len {
            if perms[at] != PERM_RW {
                at += 1;
                continue;
            }
            let start = at;
            while at < len && perms[at] == PERM_RW {
                at += 1;
            }
            // SAFETY: the run lies within this window's mapped span.
            let run = unsafe { self.base.add((first + start) * 4096) };
            let bytes = (at - start) * 4096;
            // SAFETY: as above; mprotect is async-signal-safe.
            if !super::write_tracking::protect_in_handler(run, bytes)
                || unsafe { libc::mprotect(run.cast(), bytes, libc::PROT_READ | libc::PROT_WRITE) }
                    != 0
            {
                return false;
            }
        }
        self.active[slot].store(true, Ordering::Relaxed);
        true
    }
}

impl core::fmt::Debug for NativeMemory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NativeMemory")
            .field("span", &self.span)
            .finish()
    }
}

// SAFETY: both mappings belong exclusively to this owner. Mutable access,
// including execution and permission installation, requires `&mut self`.
unsafe impl Send for NativeMemory {}
unsafe impl Sync for NativeMemory {}

impl NativeMemory {
    pub(crate) fn new(span: usize) -> Result<Self, String> {
        if span > 1usize << 32 || !span.is_multiple_of(4096) {
            return Err("invalid native guest memory span".into());
        }
        // Empty standard layouts are valid. Reserve an inaccessible native
        // page and an empty host slice without changing the logical span.
        let allocation_span = span.max(4096);
        let backing = BackingStore::new((allocation_span / 4096) as u32)
            .ok_or("failed to allocate native memory backing")?;
        let window = CodeWindow::new().ok_or("failed to reserve native memory window")?;
        // SAFETY: the fd covers `allocation_span` bytes; both mmap failures are
        // checked. MAP_FIXED replaces only this owner's reserved guest window.
        let guest = unsafe {
            libc::mmap(
                window.base().cast(),
                allocation_span,
                libc::PROT_NONE,
                libc::MAP_SHARED | libc::MAP_FIXED,
                backing.fd(),
                0,
            )
        };
        if guest == libc::MAP_FAILED {
            return Err("failed to map native guest memory".into());
        }
        let host = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                allocation_span,
                libc::PROT_READ | libc::PROT_WRITE,
                libc::MAP_SHARED,
                backing.fd(),
                0,
            )
        };
        if host == libc::MAP_FAILED {
            return Err("failed to map native host memory".into());
        }
        // Tracking is per 4 KiB page: keep both aliases off transparent huge
        // pages, which would report and protect writes per 2 MiB.
        // SAFETY: both ranges were mapped above and belong to this owner.
        unsafe {
            libc::madvise(guest, allocation_span, libc::MADV_NOHUGEPAGE);
            libc::madvise(host, allocation_span, libc::MADV_NOHUGEPAGE);
        }
        if let Err(error) = super::write_tracking::register(window.base(), allocation_span) {
            // SAFETY: the host alias was mapped above and is not yet owned.
            unsafe { libc::munmap(host, allocation_span) };
            return Err(error);
        }
        // BackingStore closes the fd now; the mappings retain the pages.
        let activation = alloc::boxed::Box::new(Activation {
            base: window.base(),
            perms: window.perms(),
            pages: span / 4096,
            active: (0..(span / 4096).div_ceil(SLOT_PAGES))
                .map(|_| AtomicBool::new(false))
                .collect(),
            failed: AtomicBool::new(false),
        });
        Ok(Self {
            host: host.cast(),
            span,
            window,
            // The window maps guest pages PROT_NONE and its permission
            // table starts zeroed.
            applied: vec![Some(0); (span / 4096).div_ceil(SLOT_PAGES)],
            synced: false,
            writable: Default::default(),
            left: Vec::new(),
            activation,
        })
    }

    pub(crate) fn window(&self) -> &CodeWindow {
        &self.window
    }

    /// Restore complete pages to zero in both aliases without instantiating
    /// every page in a newly allocated heap. MADV_REMOVE punches the pages out
    /// of this shared memfd mapping; unlike MADV_DONTNEED it discards backing
    /// contents as well. Guest permissions are unchanged.
    pub(crate) fn clear_pages(&mut self, first: usize, count: usize) -> bool {
        let Some(end) = first.checked_add(count) else {
            return false;
        };
        if end > self.span / 4096 {
            return false;
        }
        if count == 0 {
            return true;
        }
        // SAFETY: this range is page-aligned and wholly inside our writable
        // MAP_SHARED memfd alias. The only other alias belongs to this owner,
        // and no native execution can coexist with this mutable borrow.
        unsafe {
            libc::madvise(
                self.host.add(first * 4096).cast(),
                count * 4096,
                libc::MADV_REMOVE,
            ) == 0
        }
    }

    /// Bring the window's protection and permission table in line with
    /// `perms`, visiting only the slots changed since the last sync.
    pub(crate) fn sync_permissions(&mut self, perms: &mut PagePerms) -> Result<(), String> {
        let result = self.sync_permissions_inner(perms);
        if result.is_err() {
            // A partial sync leaves the window and the tracking state out of
            // step; captures stay conservative from now on.
            self.activation.failed.store(true, Ordering::Relaxed);
        }
        result
    }

    fn sync_permissions_inner(&mut self, perms: &mut PagePerms) -> Result<(), String> {
        if perms.pages() != self.span / 4096 {
            return Err("invalid native memory permissions".into());
        }
        if !self.synced {
            perms.mark_all_changed();
        }
        let window = &self.window;
        let applied = &mut self.applied;
        let left = &mut self.left;
        let writable = &mut self.writable;
        let activation = &*self.activation;
        // Whole-slot protection changes, coalesced across adjacent slots:
        // (first page, count, protection).
        let mut pending: Option<(usize, usize, libc::c_int)> = None;
        perms.drain_changed(|first, len, contents| {
            let slot = first / SLOT_PAGES;
            // Writes are tracked only in active slots; elsewhere writable
            // pages stay read-only until the guest's first write.
            let active = activation.is_active(slot);
            let enter = |first: usize, count: usize| {
                if active {
                    enter(window, first, count)
                } else {
                    Ok(())
                }
            };
            let mut leave = |first: usize, count: usize| {
                if active {
                    leave(window, left, first, count)
                } else {
                    Ok(())
                }
            };
            let protect = |first: usize, count: usize, permission: u8| {
                mprotect_pages(window, first, count, protection(permission, active))
            };
            // SAFETY: CodeWindow allocates a permission byte for every guest
            // page, and the slot lies within the span.
            let old = unsafe { core::slice::from_raw_parts_mut(window.perms().add(first), len) };

            // Pages leaving PERM_RW first report what the guest wrote to them;
            // pages entering it are write-protected before the guest can run.
            match contents {
                SlotPerms::Uniform(permission) => {
                    if applied[slot] != Some(permission) {
                        match applied[slot] {
                            Some(PERM_RW) => {
                                leave(first, len)?;
                            }
                            Some(_) if permission == PERM_RW => {
                                enter(first, len)?;
                            }
                            Some(_) => {}
                            None => {
                                let mut runs = Vec::new();
                                let now_writable = permission == PERM_RW;
                                runs_where(
                                    len,
                                    |page| (old[page] == PERM_RW) != now_writable,
                                    &mut runs,
                                );
                                for (offset, count) in runs {
                                    if now_writable {
                                        enter(first + offset, count)?;
                                    } else {
                                        leave(first + offset, count)?;
                                    }
                                }
                            }
                        }
                        let wanted = protection(permission, active);
                        match &mut pending {
                            Some((start, count, prot))
                                if *start + *count == first && *prot == wanted =>
                            {
                                *count += len;
                            }
                            _ => {
                                if let Some((start, count, prot)) =
                                    pending.replace((first, len, wanted))
                                {
                                    mprotect_pages(window, start, count, prot)?;
                                }
                            }
                        }
                        old.fill(permission);
                        applied[slot] = Some(permission);
                    }
                }
                SlotPerms::Mixed(new) => {
                    let mut page = 0;
                    while page < len {
                        if old[page] == new[page] {
                            page += 1;
                            continue;
                        }
                        let permission = new[page];
                        let mut end = page + 1;
                        while end < len && new[end] == permission && old[end] != permission {
                            end += 1;
                        }
                        if permission == PERM_RW {
                            enter(first + page, end - page)?;
                        } else {
                            let mut runs = Vec::new();
                            runs_where(
                                end - page,
                                |offset| old[page + offset] == PERM_RW,
                                &mut runs,
                            );
                            for (offset, count) in runs {
                                leave(first + page + offset, count)?;
                            }
                        }
                        protect(first + page, end - page, permission)?;
                        old[page..end].fill(permission);
                        page = end;
                    }
                    applied[slot] = None;
                }
            }
            // The slot's writable runs, from the table as now installed.
            {
                let mut runs = Vec::new();
                match applied[slot] {
                    Some(PERM_RW) => runs.push((0, len)),
                    Some(_) => {}
                    None => runs_where(len, |page| old[page] == PERM_RW, &mut runs),
                }
                let pages: usize = runs.iter().map(|run| run.1).sum();
                if !active && pages > 0 && pages <= EAGER_PAGES {
                    // The slot's own protection must land before tracking
                    // makes its writable runs writable.
                    if let Some((start, count, prot)) = pending.take() {
                        mprotect_pages(window, start, count, prot)?;
                    }
                    if !activation.start(slot) {
                        return Err("failed to start native write tracking".into());
                    }
                }
                if runs.is_empty() {
                    if !writable.is_empty() {
                        writable.remove(&slot);
                    }
                } else {
                    runs.iter_mut().for_each(|run| run.0 += first);
                    writable.insert(slot, runs);
                }
            }
            Ok(())
        })?;
        if let Some((start, count, prot)) = pending {
            mprotect_pages(window, start, count, prot)?;
        }
        self.synced = true;
        Ok(())
    }
}

/// Append the maximal runs of `[0, len)` where `selected` holds, as
/// (offset, count).
fn runs_where(len: usize, selected: impl Fn(usize) -> bool, runs: &mut Vec<(usize, usize)>) {
    let mut page = 0;
    while page < len {
        if !selected(page) {
            page += 1;
            continue;
        }
        let start = page;
        while page < len && selected(page) {
            page += 1;
        }
        runs.push((start, page - start));
    }
}

/// Report the pages of `[first, first + count)` the guest wrote, as they
/// stop being writable.
fn leave(
    window: &CodeWindow,
    left: &mut Vec<(usize, usize)>,
    first: usize,
    count: usize,
) -> Result<(), String> {
    super::write_tracking::capture(page_ptr(window, first), count * 4096, |at, bytes| {
        left.push((first + at / 4096, bytes / 4096))
    })
}

/// Write-protect `[first, first + count)` as it becomes writable.
fn enter(window: &CodeWindow, first: usize, count: usize) -> Result<(), String> {
    super::write_tracking::protect(page_ptr(window, first), count * 4096)
}

/// Window address of guest page `page`.
fn page_ptr(window: &CodeWindow, page: usize) -> *mut u8 {
    // SAFETY: callers pass pages inside the span, which the window maps.
    unsafe { window.base().add(page * 4096) }
}

impl NativeMemory {
    /// Visit the runs of pages the guest wrote through the window since the
    /// last capture, as (first page, count), and start a new period. Fails
    /// for good once tracking has failed; the caller then reports the whole
    /// span ([`Self::span_pages`]).
    pub(crate) fn take_written(&mut self, visit: impl FnMut(usize, usize)) -> Result<(), String> {
        let result = self.take_written_inner(visit);
        if result.is_err() {
            self.activation.failed.store(true, Ordering::Relaxed);
        }
        result
    }

    fn take_written_inner(&mut self, mut visit: impl FnMut(usize, usize)) -> Result<(), String> {
        if self.activation.failed.load(Ordering::Relaxed) {
            return Err("native write tracking failed earlier".into());
        }
        for (first, count) in self.left.drain(..) {
            visit(first, count);
        }
        // Only active slots can hold guest writes. Runs split at slot
        // boundaries are scanned as one range.
        let mut runs: Vec<(usize, usize)> = Vec::new();
        let activation = &*self.activation;
        let tracked = self
            .writable
            .iter()
            .filter(|(slot, _)| activation.is_active(**slot))
            .flat_map(|(_, runs)| runs);
        for &(first, count) in tracked {
            match runs.last_mut() {
                Some(last) if last.0 + last.1 == first => last.1 += count,
                _ => runs.push((first, count)),
            }
        }
        for (first, count) in runs {
            super::write_tracking::capture(
                page_ptr(&self.window, first),
                count * 4096,
                |at, bytes| visit(first + at / 4096, bytes / 4096),
            )?;
        }
        Ok(())
    }

    /// Slot activation, for the fault handler.
    pub(crate) fn activation(&self) -> *const Activation {
        &*self.activation
    }

    /// Whether write tracking has failed for good.
    pub(crate) fn tracking_failed(&self) -> bool {
        self.activation.failed.load(Ordering::Relaxed)
    }

    /// The whole span as one run, for captures once tracking has failed:
    /// reporting every page keeps the dirty set a superset of the writes.
    pub(crate) fn span_pages(&self) -> (usize, usize) {
        (0, self.span / 4096)
    }
}

/// The window protection for a guest permission. Writable pages of a slot
/// that does not track writes yet are mapped read-only.
fn protection(permission: u8, active: bool) -> libc::c_int {
    match permission {
        0 => libc::PROT_NONE,
        1 => libc::PROT_READ,
        _ if !active => libc::PROT_READ,
        _ => libc::PROT_READ | libc::PROT_WRITE,
    }
}

/// Protect `count` guest pages from `first` in the window.
fn mprotect_pages(
    window: &CodeWindow,
    first: usize,
    count: usize,
    protection: libc::c_int,
) -> Result<(), String> {
    // SAFETY: the page-aligned range belongs to this native alias.
    if unsafe {
        libc::mprotect(
            window.base().add(first * 4096).cast(),
            count * 4096,
            protection,
        )
    } != 0
    {
        return Err("failed to install native memory permissions".into());
    }
    Ok(())
}

impl core::ops::Deref for NativeMemory {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        // SAFETY: the host alias remains readable for its full lifetime.
        unsafe { core::slice::from_raw_parts(self.host, self.span) }
    }
}

impl NativeMemory {
    /// The host alias, for writes. Every write through it must also mark
    /// the written pages dirty; only `FlatMem`'s write paths call this.
    pub(crate) fn host_ptr(&mut self) -> *mut u8 {
        self.host
    }

    #[cfg(test)]
    fn poke(&mut self, offset: usize, byte: u8) {
        assert!(offset < self.span);
        // SAFETY: bounds-checked above; exclusive owner access.
        unsafe { *self.host.add(offset) = byte };
    }
}

impl Drop for NativeMemory {
    fn drop(&mut self) {
        // SAFETY: this exact mapping was allocated by `new` and is owned here.
        unsafe {
            libc::munmap(self.host.cast(), self.span.max(4096));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// What the fault handler does on a guest's first write to `page`:
    /// start tracking its slot unless it already tracks writes.
    fn first_write(memory: &NativeMemory, page: usize) {
        // SAFETY: the activation lives as long as `memory`.
        let activation = unsafe { &*memory.activation() };
        if !activation.is_active(page / SLOT_PAGES) {
            assert!(matches!(activation.activate(page), Activated::Started));
        }
    }

    #[test]
    fn aliases_share_values_and_permissions_never_restrict_host_initialization() {
        let mut memory = NativeMemory::new(3 * 4096).unwrap();
        let mut perms = PagePerms::new_rw(3);
        let mut install = |memory: &mut NativeMemory, map: &[u8]| {
            perms.install(map.to_vec());
            memory.sync_permissions(&mut perms)
        };
        memory.poke(4096, 17);
        install(&mut memory, &[0, 1, 2]).unwrap();
        // SAFETY: the guest's middle page was made readable above.
        assert_eq!(unsafe { *memory.window().base().add(4096) }, 17);
        memory.poke(4096, 23);
        assert_eq!(unsafe { *memory.window().base().add(4096) }, 23);
        // SAFETY: the guest's last page was made writable above; its slot
        // starts tracking writes as the fault handler would.
        first_write(&memory, 2);
        unsafe {
            *memory.window().base().add(8192) = 31;
        }
        assert_eq!(memory[8192], 31);
        install(&mut memory, &[0, 0, 0]).unwrap();
        assert_eq!(memory[4096], 23, "unmapping does not erase logical values");
        assert!(memory.clear_pages(1, 2));
        assert_eq!(
            memory[8192], 0,
            "clear removes data even while the native alias is inaccessible"
        );
        install(&mut memory, &[0, 1, 0]).unwrap();
        assert_eq!(unsafe { *memory.window().base().add(4096) }, 0);
        let permissions = unsafe { core::slice::from_raw_parts(memory.window().perms(), 4) };
        assert_eq!(
            permissions,
            [0, 1, 0, 0],
            "out-of-span remains inaccessible"
        );
        memory.poke(4096, 55);
        assert!(memory.clear_pages(1, 1));
        assert_eq!(
            unsafe { *memory.window().base().add(4096) },
            0,
            "clearing also zeroes a currently read-only native alias"
        );
        install(&mut memory, &[0, 2, 0]).unwrap();
        // SAFETY: the middle page is writable and its slot tracks writes.
        unsafe {
            *memory.window().base().add(4096) = 77;
        }
        assert_eq!(memory[4096], 77, "reallocation retains shared aliasing");
    }

    #[test]
    fn a_map_applies_fully_to_any_new_window() {
        let window_table = |memory: &NativeMemory| {
            // SAFETY: the window holds a permission byte per guest page.
            unsafe { core::slice::from_raw_parts(memory.window().perms(), 3) }.to_vec()
        };
        let mut perms = PagePerms::new_rw(3);
        perms.install(vec![0, 1, 2]);
        let mut first = NativeMemory::new(3 * 4096).unwrap();
        first.sync_permissions(&mut perms).unwrap();
        assert_eq!(window_table(&first), [0, 1, 2]);

        // The drained map, and a clone of it, still install fully on a
        // window that has never seen them.
        let mut fresh = NativeMemory::new(3 * 4096).unwrap();
        fresh.sync_permissions(&mut perms).unwrap();
        assert_eq!(window_table(&fresh), [0, 1, 2]);
        let mut clone = perms.clone();
        clone.install(vec![2, 2, 2]);
        let mut other = NativeMemory::new(3 * 4096).unwrap();
        other.sync_permissions(&mut perms.clone()).unwrap();
        assert_eq!(window_table(&other), [0, 1, 2]);
        first.sync_permissions(&mut clone).unwrap();
        assert_eq!(window_table(&first), [2, 2, 2]);
        // SAFETY: every page of the first window is now writable; the store
        // starts tracking its slot as the fault handler would.
        first_write(&first, 2);
        unsafe {
            *first.window().base().add(2 * 4096) = 9;
        }
        assert_eq!(first[2 * 4096], 9);
    }

    #[test]
    fn guest_writes_are_captured_across_permission_changes() {
        let mut memory = NativeMemory::new(4 * 4096).unwrap();
        let mut perms = PagePerms::new_rw(4);
        let mut sync = |memory: &mut NativeMemory, map: &[u8]| {
            perms.install(map.to_vec());
            memory.sync_permissions(&mut perms).unwrap();
        };
        // A guest store: its first write into a slot starts tracking there,
        // as the fault handler does.
        let guest_store = |memory: &NativeMemory, address: usize| {
            first_write(memory, address / 4096);
            // SAFETY: tests store only to pages installed writable.
            unsafe { core::ptr::write_volatile(memory.window().base().add(address), 1) }
        };
        let captured = |memory: &mut NativeMemory| {
            let mut runs = Vec::new();
            memory
                .take_written(|first, count| runs.push((first, count)))
                .unwrap();
            runs.sort();
            runs
        };

        sync(&mut memory, &[0, 2, 2, 1]);
        guest_store(&memory, 4096);
        guest_store(&memory, 2 * 4096 + 5);
        // Page 1 stops being writable before the capture.
        sync(&mut memory, &[0, 1, 2, 1]);
        assert_eq!(captured(&mut memory), [(1, 1), (2, 1)]);
        assert!(
            captured(&mut memory).is_empty(),
            "capture starts a new period"
        );

        // Host writes go through the other alias and are not guest writes.
        memory.poke(2 * 4096, 3);
        assert!(captured(&mut memory).is_empty());

        // Pages that become writable are tracked from then on.
        sync(&mut memory, &[2, 2, 2, 2]);
        guest_store(&memory, 0);
        guest_store(&memory, 3 * 4096 + 9);
        assert_eq!(captured(&mut memory), [(0, 1), (3, 1)]);
    }

    fn captured(memory: &mut NativeMemory) -> Result<Vec<(usize, usize)>, String> {
        let mut runs = Vec::new();
        memory.take_written(|first, count| runs.push((first, count)))?;
        runs.sort();
        Ok(runs)
    }

    #[test]
    fn large_slots_track_from_the_first_write_and_survive_clears() {
        let pages = 2 * SLOT_PAGES;
        let mut memory = NativeMemory::new(pages * 4096).unwrap();
        let mut perms = PagePerms::new_rw(pages);
        memory.sync_permissions(&mut perms).unwrap();
        // SAFETY: the activation lives as long as `memory`.
        let activation = unsafe { &*memory.activation() };
        assert!(!activation.is_active(0), "a large slot waits for a write");
        let store = |memory: &NativeMemory, page: usize| {
            first_write(memory, page);
            // SAFETY: every page is writable and its slot now tracks writes.
            unsafe { core::ptr::write_volatile(memory.window().base().add(page * 4096), 1) }
        };

        store(&memory, 7);
        assert!(!activation.is_active(1), "only the written slot tracks");
        assert_eq!(captured(&mut memory).unwrap(), [(7, 1)]);

        // A host clear punches the page out of both aliases; the next guest
        // write to it is still reported.
        assert!(memory.clear_pages(7, 1));
        assert_eq!(captured(&mut memory).unwrap(), []);
        store(&memory, 7);
        assert_eq!(captured(&mut memory).unwrap(), [(7, 1)]);
    }

    #[test]
    fn a_fault_in_a_tracking_slot_fails_tracking_for_good() {
        let mut memory = NativeMemory::new(4 * 4096).unwrap();
        let mut perms = PagePerms::new_rw(4);
        memory.sync_permissions(&mut perms).unwrap();
        // SAFETY: the activation lives as long as `memory`.
        let activation = unsafe { &*memory.activation() };
        assert!(activation.is_active(0), "a small slot tracks at once");
        // The window maps a tracking slot's writable pages writable, so a
        // write fault there means tracking and protection disagree.
        assert!(matches!(activation.activate(1), Activated::Failed));
        assert!(captured(&mut memory).is_err());
        assert!(captured(&mut memory).is_err(), "the failure is permanent");
        assert_eq!(memory.span_pages(), (0, 4));
    }

    #[test]
    fn zero_span_is_empty_and_bad_permission_maps_fail_explicitly() {
        let mut memory = NativeMemory::new(0).unwrap();
        assert!(memory.is_empty());
        memory.sync_permissions(&mut PagePerms::new_rw(0)).unwrap();
        assert!(memory.clear_pages(0, 0));
        assert!(!memory.clear_pages(0, 1));
        assert!(!memory.clear_pages(usize::MAX, 1));
        assert!(memory.sync_permissions(&mut PagePerms::new_rw(1)).is_err());
        assert!(NativeMemory::new(1).is_err());
        assert!(NativeMemory::new((1usize << 32) + 4096).is_err());
    }
}
