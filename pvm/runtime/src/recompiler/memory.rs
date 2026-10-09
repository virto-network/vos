//! Two views of one invocation's memory: checked host access and protected JIT access.
//!
//! Both aliases share lazily allocated pages. Native execution never sees the
//! unprotected host alias, and host reads/clears retain `Memory`'s semantics even
//! for pages which are inaccessible to the guest. Neither alias owns a dense
//! allocation or a live file descriptor after construction.

use crate::backing::{BackingStore, CodeWindow};
use crate::interpreter::memory::{PagePerms, SLOT_PAGES, SlotPerms};

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
        // BackingStore closes the fd now; the mappings retain the pages.
        Ok(Self {
            host: host.cast(),
            span,
            window,
            // The window maps guest pages PROT_NONE and its permission
            // table starts zeroed.
            applied: vec![Some(0); (span / 4096).div_ceil(SLOT_PAGES)],
            synced: false,
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
        if perms.pages() != self.span / 4096 {
            return Err("invalid native memory permissions".into());
        }
        if !self.synced {
            perms.mark_all_changed();
        }
        let window = &self.window;
        let applied = &mut self.applied;
        perms.drain_changed(|first, len, contents| {
            let slot = first / SLOT_PAGES;
            // SAFETY: CodeWindow allocates a permission byte for every guest
            // page, and the slot lies within the span.
            let old = unsafe { core::slice::from_raw_parts_mut(window.perms().add(first), len) };
            match contents {
                SlotPerms::Uniform(permission) => {
                    if applied[slot] != Some(permission) {
                        protect(window, first, len, permission)?;
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
                        protect(window, first + page, end - page, permission)?;
                        old[page..end].fill(permission);
                        page = end;
                    }
                    applied[slot] = None;
                }
            }
            Ok(())
        })?;
        self.synced = true;
        Ok(())
    }
}

/// Protect `count` guest pages from `first` in the window.
fn protect(window: &CodeWindow, first: usize, count: usize, permission: u8) -> Result<(), String> {
    let protection = match permission {
        0 => libc::PROT_NONE,
        1 => libc::PROT_READ,
        _ => libc::PROT_READ | libc::PROT_WRITE,
    };
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

impl core::ops::DerefMut for NativeMemory {
    fn deref_mut(&mut self) -> &mut [u8] {
        // SAFETY: exclusive owner access; native execution cannot be concurrent.
        unsafe { core::slice::from_raw_parts_mut(self.host, self.span) }
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

    #[test]
    fn aliases_share_values_and_permissions_never_restrict_host_initialization() {
        let mut memory = NativeMemory::new(3 * 4096).unwrap();
        let mut perms = PagePerms::new_rw(3);
        let mut install = |memory: &mut NativeMemory, map: &[u8]| {
            perms.install(map.to_vec());
            memory.sync_permissions(&mut perms)
        };
        memory[4096] = 17;
        install(&mut memory, &[0, 1, 2]).unwrap();
        // SAFETY: the guest's middle page was made readable above.
        assert_eq!(unsafe { *memory.window().base().add(4096) }, 17);
        memory[4096] = 23;
        assert_eq!(unsafe { *memory.window().base().add(4096) }, 23);
        // SAFETY: the guest's last page was made writable above.
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
        memory[4096] = 55;
        assert!(memory.clear_pages(1, 1));
        assert_eq!(
            unsafe { *memory.window().base().add(4096) },
            0,
            "clearing also zeroes a currently read-only native alias"
        );
        install(&mut memory, &[0, 2, 0]).unwrap();
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
        // SAFETY: every page of the first window is now writable.
        unsafe { *first.window().base().add(2 * 4096) = 9 };
        assert_eq!(first[2 * 4096], 9);
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
