//! Guest memory representations for the interpreter.
//!
//! [`Memory`] is the seam between the interpreter's load/store path and the
//! bytes backing the 32-bit guest address space:
//!
//! - [`FlatMem`] is the historical representation — one dense buffer from
//!   address 0 to the end of the highest mapped page. It is the fastest
//!   form (one bounds check plus a raw unaligned access) and the only one
//!   the kernel and recompiler paths construct. On 64-bit hosts a mostly
//!   untouched multi-GiB buffer is cheap (lazily-zeroed pages).
//! - [`SparseMem`] maps 4 KiB guest pages to frames in a dense arena,
//!   allocating a frame on first write; reads of untouched pages yield
//!   zero, exactly like the zero-initialized flat buffer. It exists for
//!   32-bit embedders (e.g. wasm32 runtimes): GP's standard-program layout
//!   places the stack and argument regions just below 2³², so the flat
//!   image of any real SPI program spans ~4 GiB — unallocatable inside a
//!   32-bit heap. Sparse allocation is O(touched pages) plus a fixed
//!   page/frame table (~5 MiB for a full 4 GiB span).
//!
//! Both variants share [`PagePerms`] for the per-page permission map, so
//! access classification — which accesses fault, and the reported faulting
//! page base — is identical by construction. The two representations are
//! semantically indistinguishable: same reads, same writes, same faults,
//! and identical gas (gas derives from declared pages, never from
//! allocated bytes). This is pinned by differential tests here and in
//! `refine`.

use alloc::{vec, vec::Vec};

use super::{PERM_NONE, PERM_RW};
use crate::PVM_PAGE_SIZE;

const PAGE: usize = PVM_PAGE_SIZE as usize;

/// One non-zero page in a canonical sparse memory image.
///
/// Images are ordered by `page_index` and never contain an all-zero page.
/// Keeping this representation at the interpreter boundary lets proof
/// tracers snapshot a 32-bit guest address space without materialising its
/// mostly-zero, nearly 4 GiB logical byte image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NonZeroPage {
    pub page_index: u32,
    pub bytes: [u8; PAGE],
}

/// Deterministic sparse value image of guest memory.
///
/// Permissions are intentionally not part of the value image. Callers that
/// commit complete architectural state must bind `Memory::page_perms`
/// separately.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SparseMemoryImage {
    span: u64,
    pages: Vec<NonZeroPage>,
}

impl SparseMemoryImage {
    /// Construct a canonical image. Returns `None` for an invalid span,
    /// unordered/duplicate/out-of-range pages, or an all-zero listed page.
    pub fn new(span: u64, pages: Vec<NonZeroPage>) -> Option<Self> {
        if span > 1u64 << 32 || !span.is_multiple_of(PAGE as u64) {
            return None;
        }
        let page_count = span / PAGE as u64;
        let mut previous = None;
        for page in &pages {
            if u64::from(page.page_index) >= page_count
                || previous.is_some_and(|p| p >= page.page_index)
                || page.bytes.iter().all(|&byte| byte == 0)
            {
                return None;
            }
            previous = Some(page.page_index);
        }
        Some(Self { span, pages })
    }

    pub fn span(&self) -> u64 {
        self.span
    }

    pub fn pages(&self) -> &[NonZeroPage] {
        &self.pages
    }

    /// Return a page by index, or an all-zero page when it is absent.
    pub fn page(&self, page_index: u32) -> [u8; PAGE] {
        self.pages
            .binary_search_by_key(&page_index, |page| page.page_index)
            .ok()
            .map_or([0; PAGE], |index| self.pages[index].bytes)
    }

    /// Read one logical byte. Out-of-span addresses read as zero, matching
    /// [`Memory::read_bytes`].
    pub fn byte(&self, address: u32) -> u8 {
        if u64::from(address) >= self.span {
            return 0;
        }
        let page_index = address / PVM_PAGE_SIZE;
        let offset = (address % PVM_PAGE_SIZE) as usize;
        self.pages
            .binary_search_by_key(&page_index, |page| page.page_index)
            .ok()
            .map_or(0, |index| self.pages[index].bytes[offset])
    }

    /// Apply bytes to the logical image while preserving canonical ordering
    /// and dropping pages that become all-zero.
    pub fn write(&mut self, address: u32, mut bytes: &[u8]) -> bool {
        let Some(end) = u64::from(address).checked_add(bytes.len() as u64) else {
            return false;
        };
        if end > self.span {
            return false;
        }
        let mut cursor = u64::from(address);
        while !bytes.is_empty() {
            let page_index = (cursor / PAGE as u64) as u32;
            let offset = (cursor % PAGE as u64) as usize;
            let len = (PAGE - offset).min(bytes.len());
            let search = self
                .pages
                .binary_search_by_key(&page_index, |page| page.page_index);
            let index = match search {
                Ok(index) => index,
                Err(index) => {
                    if bytes[..len].iter().all(|&byte| byte == 0) {
                        cursor += len as u64;
                        bytes = &bytes[len..];
                        continue;
                    }
                    self.pages.insert(
                        index,
                        NonZeroPage {
                            page_index,
                            bytes: [0; PAGE],
                        },
                    );
                    index
                }
            };
            self.pages[index].bytes[offset..offset + len].copy_from_slice(&bytes[..len]);
            if self.pages[index].bytes.iter().all(|&byte| byte == 0) {
                self.pages.remove(index);
            }
            cursor += len as u64;
            bytes = &bytes[len..];
        }
        true
    }
}

/// Pages per slot of the two-level page tables.
pub(crate) const SLOT_PAGES: usize = 1 << 10;

/// One slot of [`PagePerms`]: 1,024 consecutive pages.
#[derive(Clone, Debug)]
enum PermSlot {
    /// Every page in the slot has this permission.
    Uniform(u8),
    /// Per-page permissions. Entries past the end of the span are unused.
    Mixed(alloc::boxed::Box<[u8; SLOT_PAGES]>),
}

/// Per-page access map shared by every memory representation.
///
/// Mirrors the recompiler's hardware page protection (PROT_NONE /
/// PROT_READ / PROT_READ|WRITE): reads need at least [`super::PERM_RO`],
/// writes need [`PERM_RW`], and any access touching an unmapped page
/// faults. Failures report the offending page base — GP page faults are
/// page-granular, matching the Lean oracle and the JIT's SIGSEGV path.
///
/// The map is a two-level table: slots of 1,024 pages that are either
/// uniform or hold one byte per page. Laying out or unmapping whole slots
/// keeps them uniform, so the cost of a 4 GiB address space is proportional
/// to the pages with distinct permissions, never to the span.
///
/// All address arithmetic is done in `u64`: `addr + n - 1` may exceed
/// `u32::MAX` for a wide access at the top of the address space, and on
/// 32-bit hosts a `usize` sum would wrap and defeat the bounds check.
#[derive(Debug, Default)]
pub struct PagePerms {
    pages: usize,
    slots: Vec<PermSlot>,
    /// True when every page is [`PERM_RW`]. In that (common) case a
    /// mapped-page bounds check subsumes the permission check, so the
    /// accessors skip the table walk — the flat-buffer fast path for
    /// programs with no read-only or unmapped pages.
    uniform_rw: bool,
    /// Slots that are not uniformly [`PERM_RW`]; `uniform_rw` holds when
    /// there are none.
    not_rw: usize,
    /// Monotonic mutation counter used by proof observers to cache the
    /// canonical permission commitment without rescanning the page table at
    /// every host boundary.
    revision: u64,
    /// Slots changed since the native window last applied them, one bit per
    /// slot. The bits describe this map's own window only: a clone starts
    /// with every slot changed, and a fresh window applies every slot.
    changed: Vec<u64>,
    /// Slots changed since the last [`Self::take_touched_slots`], one bit
    /// per slot, for resetting a pooled machine's permissions.
    touched: Vec<u64>,
}

impl Clone for PagePerms {
    fn clone(&self) -> Self {
        Self {
            pages: self.pages,
            slots: self.slots.clone(),
            uniform_rw: self.uniform_rw,
            not_rw: self.not_rw,
            revision: self.revision,
            changed: vec![u64::MAX; self.changed.len()],
            touched: self.touched.clone(),
        }
    }
}

impl PagePerms {
    fn new(pages: usize, permission: u8) -> Self {
        let slots = pages.div_ceil(SLOT_PAGES);
        Self {
            pages,
            slots: vec![PermSlot::Uniform(permission); slots],
            uniform_rw: permission == PERM_RW,
            not_rw: if permission == PERM_RW { 0 } else { slots },
            revision: 0,
            changed: vec![u64::MAX; slots.div_ceil(64)],
            touched: vec![0; slots.div_ceil(64)],
        }
    }

    pub(crate) fn new_rw(pages: usize) -> Self {
        Self::new(pages, PERM_RW)
    }

    /// Pages of slot `slot` that lie inside the span.
    #[inline(always)]
    fn slot_len(&self, slot: usize) -> usize {
        (self.pages - slot * SLOT_PAGES).min(SLOT_PAGES)
    }

    /// The permission of page `page`, which must be inside the span.
    #[inline(always)]
    fn get(&self, page: usize) -> u8 {
        // SAFETY: callers check page < self.pages, and slots cover every
        // page in the span.
        match unsafe { self.slots.get_unchecked(page / SLOT_PAGES) } {
            PermSlot::Uniform(permission) => *permission,
            PermSlot::Mixed(leaf) => leaf[page % SLOT_PAGES],
        }
    }

    /// Replace the whole map with one entry per page.
    pub(crate) fn install(&mut self, perms: Vec<u8>) {
        let mut modified = false;
        for slot in 0..self.slots.len() {
            let start = slot * SLOT_PAGES;
            let chunk = &perms[start..start + self.slot_len(slot)];
            modified |= self.write_slot(slot, 0, chunk.len(), |page| chunk[page]);
        }
        if modified {
            self.after_change();
        }
    }

    #[inline(always)]
    pub(crate) fn pages(&self) -> usize {
        self.pages
    }

    #[inline(always)]
    fn revision(&self) -> u64 {
        self.revision
    }

    /// Set `count` pages from `first` to `permission`.
    fn set_range(&mut self, first: usize, count: usize, permission: u8) {
        let mut modified = false;
        let end = first + count;
        let mut page = first;
        while page < end {
            let slot = page / SLOT_PAGES;
            let lo = page - slot * SLOT_PAGES;
            let hi = (end - slot * SLOT_PAGES).min(self.slot_len(slot));
            modified |= self.write_slot(slot, lo, hi, |_| permission);
            page = slot * SLOT_PAGES + hi;
        }
        if modified {
            self.after_change();
        }
    }

    /// Write pages `[lo, hi)` of `slot` from `value(index)`, where the index
    /// counts from `lo`. Keeps a slot uniform when the result is. Returns
    /// whether any permission changed.
    fn write_slot(
        &mut self,
        slot: usize,
        lo: usize,
        hi: usize,
        value: impl Fn(usize) -> u8,
    ) -> bool {
        if lo == hi {
            return false;
        }
        let len = self.slot_len(slot);
        let first = value(0);
        let all_same = (lo..hi).all(|page| value(page - lo) == first);
        let unchanged = match &self.slots[slot] {
            PermSlot::Uniform(existing) => all_same && *existing == first,
            PermSlot::Mixed(leaf) => (lo..hi).all(|page| leaf[page] == value(page - lo)),
        };
        if unchanged {
            return false;
        }
        let was_rw = matches!(self.slots[slot], PermSlot::Uniform(PERM_RW));
        if lo == 0 && hi == len && all_same {
            self.slots[slot] = PermSlot::Uniform(first);
        } else {
            if let PermSlot::Uniform(existing) = self.slots[slot] {
                self.slots[slot] = PermSlot::Mixed(alloc::boxed::Box::new([existing; SLOT_PAGES]));
            }
            let PermSlot::Mixed(leaf) = &mut self.slots[slot] else {
                unreachable!("slot materialized above");
            };
            for page in lo..hi {
                leaf[page] = value(page - lo);
            }
            if leaf[..len].iter().all(|&permission| permission == leaf[0]) {
                self.slots[slot] = PermSlot::Uniform(leaf[0]);
            }
        }
        match (
            was_rw,
            matches!(self.slots[slot], PermSlot::Uniform(PERM_RW)),
        ) {
            (true, false) => self.not_rw += 1,
            (false, true) => self.not_rw -= 1,
            _ => {}
        }
        self.changed[slot / 64] |= 1 << (slot % 64);
        self.touched[slot / 64] |= 1 << (slot % 64);
        true
    }

    fn after_change(&mut self) {
        self.uniform_rw = self.not_rw == 0;
        self.revision = self
            .revision
            .checked_add(1)
            .expect("permission revision cannot wrap in one invocation");
    }

    /// The slots changed since the last call, in order.
    pub(crate) fn take_touched_slots(&mut self) -> Vec<usize> {
        let mut slots = Vec::new();
        for (word, bits) in self.touched.iter_mut().enumerate() {
            while *bits != 0 {
                slots.push(word * 64 + bits.trailing_zeros() as usize);
                *bits &= *bits - 1;
            }
        }
        slots
    }

    /// Maximal runs `(first page, count, permission)` of one slot's pages.
    pub(crate) fn slot_runs(&self, slot: usize) -> Vec<(usize, usize, u8)> {
        let base = slot * SLOT_PAGES;
        match &self.slots[slot] {
            PermSlot::Uniform(permission) => alloc::vec![(base, self.slot_len(slot), *permission)],
            PermSlot::Mixed(leaf) => {
                let mut runs: Vec<(usize, usize, u8)> = Vec::new();
                for (offset, &permission) in leaf[..self.slot_len(slot)].iter().enumerate() {
                    match runs.last_mut() {
                        Some((_, len, last)) if *last == permission => *len += 1,
                        _ => runs.push((base + offset, 1, permission)),
                    }
                }
                runs
            }
        }
    }

    /// Maximal runs `(first page, count, permission)` covering the span in
    /// order. This is the canonical form of the map.
    pub(crate) fn runs(&self) -> Vec<(usize, usize, u8)> {
        let mut runs: Vec<(usize, usize, u8)> = Vec::new();
        let mut push = |page: usize, count: usize, permission: u8| match runs.last_mut() {
            Some((first, len, last)) if *last == permission && *first + *len == page => {
                *len += count;
            }
            _ => runs.push((page, count, permission)),
        };
        for (slot, entry) in self.slots.iter().enumerate() {
            let base = slot * SLOT_PAGES;
            match entry {
                PermSlot::Uniform(permission) => push(base, self.slot_len(slot), *permission),
                PermSlot::Mixed(leaf) => {
                    for (offset, &permission) in leaf[..self.slot_len(slot)].iter().enumerate() {
                        push(base + offset, 1, permission);
                    }
                }
            }
        }
        runs
    }

    /// Mark every slot changed, so the next drain visits the whole map.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn mark_all_changed(&mut self) {
        self.changed.fill(u64::MAX);
    }

    /// Visit each slot changed since the last visit, with its first page,
    /// its length inside the span and its contents, then forget the changes.
    /// A slot whose visit fails stays changed; the failure is fatal to the
    /// invocation, so the partially applied slot is never executed.
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn drain_changed(
        &mut self,
        mut visit: impl FnMut(usize, usize, SlotPerms<'_>) -> Result<(), alloc::string::String>,
    ) -> Result<(), alloc::string::String> {
        for word in 0..self.changed.len() {
            while self.changed[word] != 0 {
                let bit = self.changed[word].trailing_zeros() as usize;
                let slot = word * 64 + bit;
                if slot < self.slots.len() {
                    let contents = match &self.slots[slot] {
                        PermSlot::Uniform(permission) => SlotPerms::Uniform(*permission),
                        PermSlot::Mixed(leaf) => SlotPerms::Mixed(&leaf[..self.slot_len(slot)]),
                    };
                    visit(slot * SLOT_PAGES, self.slot_len(slot), contents)?;
                }
                self.changed[word] &= !(1 << bit);
            }
        }
        Ok(())
    }

    // Native scalar loads/stores reach this through standard exception
    // classification. Inlining exposes their constant width/permission;
    // keep the portable guest compilation unchanged.
    #[cfg_attr(feature = "std", inline(always))]
    fn range_has_at_least(&self, addr: u32, len: usize, permission: u8) -> bool {
        if len == 0 {
            return true;
        }
        let Some(end) = (addr as u64).checked_add(len as u64) else {
            return false;
        };
        if end > self.pages as u64 * PAGE as u64 {
            return false;
        }
        let first = (addr as usize) / PAGE;
        let last = ((end - 1) as usize) / PAGE;
        self.pages_have_at_least(first, last + 1, permission)
    }

    /// Whether pages `[first, end)`, which must lie in the span, all have at
    /// least `permission`.
    fn pages_have_at_least(&self, first: usize, end: usize, permission: u8) -> bool {
        let mut page = first;
        while page < end {
            let slot = page / SLOT_PAGES;
            let slot_end = ((slot + 1) * SLOT_PAGES).min(end);
            match &self.slots[slot] {
                PermSlot::Uniform(existing) => {
                    if *existing < permission {
                        return false;
                    }
                }
                PermSlot::Mixed(leaf) => {
                    let base = slot * SLOT_PAGES;
                    if leaf[page - base..slot_end - base]
                        .iter()
                        .any(|&existing| existing < permission)
                    {
                        return false;
                    }
                }
            }
            page = slot_end;
        }
        true
    }

    /// True when the last byte of `[addr, addr+n)` is on a mapped page
    /// (bounds check). Under uniform-RW memory this subsumes both
    /// readable/writable.
    #[inline(always)]
    fn in_bounds(&self, addr: u32, n: usize) -> bool {
        ((addr as u64 + n as u64 - 1) >> 12) < self.pages as u64
    }

    /// True when `[addr, addr+n)` is entirely on readable pages.
    #[inline(always)]
    fn readable(&self, addr: u32, n: usize) -> bool {
        if self.uniform_rw {
            return self.in_bounds(addr, n);
        }
        let page = (addr >> 12) as usize;
        if page >= self.pages || self.get(page) == PERM_NONE {
            return false;
        }
        if (addr as usize & 0xFFF) + n > PAGE {
            let last = page + 1;
            return last < self.pages && self.get(last) != PERM_NONE;
        }
        true
    }

    /// True when `[addr, addr+n)` is entirely on writable pages.
    #[inline(always)]
    fn writable(&self, addr: u32, n: usize) -> bool {
        if self.uniform_rw {
            return self.in_bounds(addr, n);
        }
        let page = (addr >> 12) as usize;
        if page >= self.pages || self.get(page) != PERM_RW {
            return false;
        }
        if (addr as usize & 0xFFF) + n > PAGE {
            let last = page + 1;
            return last < self.pages && self.get(last) == PERM_RW;
        }
        true
    }

    /// Page base of the first page in `[addr, addr+n)` that fails the
    /// access check. Only called after a failed access (cold path).
    #[cold]
    fn fault_page(&self, addr: u32, n: usize, write: bool) -> u32 {
        let ok = |p: u64| {
            (p as usize) < self.pages
                && if write {
                    self.get(p as usize) == PERM_RW
                } else {
                    self.get(p as usize) != PERM_NONE
                }
        };
        let first = (addr >> 12) as u64;
        let page = if ok(first) {
            (addr as u64 + n as u64 - 1) >> 12
        } else {
            first
        };
        (page << 12) as u32
    }

    fn allocated_bytes(&self) -> usize {
        self.slots.capacity() * core::mem::size_of::<PermSlot>()
            + self
                .slots
                .iter()
                .filter(|slot| matches!(slot, PermSlot::Mixed(_)))
                .count()
                * SLOT_PAGES
            + self.changed.capacity() * core::mem::size_of::<u64>()
    }
}

/// The contents of one permission slot, as visited by
/// [`PagePerms::drain_changed`].
#[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
pub(crate) enum SlotPerms<'a> {
    Uniform(u8),
    Mixed(&'a [u8]),
}

/// One slot of [`DirtyPages`].
#[derive(Clone, Debug, Default)]
enum DirtySlot {
    #[default]
    Clean,
    /// One bit per page of the slot written since the last capture.
    Pages(alloc::boxed::Box<[u64; SLOT_PAGES / 64]>),
    /// Every page of the slot counts as written.
    Full,
}

/// Pages written since the last capture, by the guest or the host.
///
/// A two-level bitmap of 1,024-page slots, allocated on a slot's first
/// write. A range covering whole slots marks them in one step, so clearing
/// a large range costs one entry per slot, never one per page.
#[derive(Clone, Debug, Default)]
struct DirtyPages {
    pages: usize,
    slots: Vec<DirtySlot>,
    /// Slots that are not clean, in first-write order.
    touched: Vec<u32>,
    /// One past the page marked last (zero: none), so repeated stores to
    /// one page skip the walk.
    last: usize,
}

impl DirtyPages {
    fn new(pages: usize) -> Self {
        Self {
            pages,
            slots: vec![DirtySlot::Clean; pages.div_ceil(SLOT_PAGES)],
            touched: Vec::new(),
            last: 0,
        }
    }

    /// Mark page `page`, which must be inside the span.
    #[inline(always)]
    fn mark(&mut self, page: usize) {
        if page + 1 == self.last {
            return;
        }
        self.last = page + 1;
        let slot = page / SLOT_PAGES;
        let bit = page % SLOT_PAGES;
        match &mut self.slots[slot] {
            DirtySlot::Pages(bits) => bits[bit / 64] |= 1 << (bit % 64),
            DirtySlot::Full => {}
            clean @ DirtySlot::Clean => {
                let mut bits = alloc::boxed::Box::new([0; SLOT_PAGES / 64]);
                bits[bit / 64] = 1 << (bit % 64);
                *clean = DirtySlot::Pages(bits);
                self.touched.push(slot as u32);
            }
        }
    }

    /// Mark the pages holding `[addr, addr + len)`, which must be inside
    /// the span. An access is at most 8 bytes, so it spans one or two pages.
    #[inline(always)]
    fn mark_access(&mut self, addr: u32, len: usize) {
        let page = (addr >> 12) as usize;
        self.mark(page);
        if (addr as usize & 0xFFF) + len > PAGE {
            self.mark(page + 1);
        }
    }

    /// Mark `count` pages from `first`, which must lie inside the span.
    fn mark_range(&mut self, first: usize, count: usize) {
        let end = first + count;
        let mut page = first;
        while page < end {
            let slot = page / SLOT_PAGES;
            let base = slot * SLOT_PAGES;
            let slot_end = (base + SLOT_PAGES).min(self.pages);
            let hi = end.min(slot_end);
            if page == base && hi == slot_end {
                if matches!(self.slots[slot], DirtySlot::Clean) {
                    self.touched.push(slot as u32);
                }
                self.slots[slot] = DirtySlot::Full;
            } else {
                for page in page..hi {
                    self.mark(page);
                }
            }
            page = hi;
        }
    }

    /// The marked pages as sorted, coalesced ranges, clearing the marks.
    fn take(&mut self) -> Vec<core::ops::Range<u32>> {
        self.last = 0;
        let mut touched = core::mem::take(&mut self.touched);
        touched.sort_unstable();
        let mut ranges: Vec<core::ops::Range<u32>> = Vec::new();
        let mut push = |page: usize, count: usize| {
            let (first, end) = (page as u32, (page + count) as u32);
            match ranges.last_mut() {
                Some(last) if last.end == first => last.end = end,
                _ => ranges.push(first..end),
            }
        };
        for slot in touched {
            let slot = slot as usize;
            let base = slot * SLOT_PAGES;
            match core::mem::take(&mut self.slots[slot]) {
                DirtySlot::Clean => {}
                DirtySlot::Full => push(base, (base + SLOT_PAGES).min(self.pages) - base),
                DirtySlot::Pages(bits) => {
                    for (index, &word) in bits.iter().enumerate() {
                        let mut word = word;
                        while word != 0 {
                            push(base + index * 64 + word.trailing_zeros() as usize, 1);
                            word &= word - 1;
                        }
                    }
                }
            }
        }
        ranges
    }

    fn allocated_bytes(&self) -> usize {
        self.slots.capacity() * core::mem::size_of::<DirtySlot>()
            + self
                .slots
                .iter()
                .filter(|slot| matches!(slot, DirtySlot::Pages(_)))
                .count()
                * SLOT_PAGES
                / 8
            + self.touched.capacity() * core::mem::size_of::<u32>()
    }
}

/// Dense guest memory: one buffer spanning address 0 to the end of the
/// highest mapped page. Always a whole number of 4 KiB pages; the
/// permission map has exactly one entry per page, so the page-index bounds
/// check doubles as the byte-range check.
#[derive(Clone, Debug, Default)]
pub struct FlatMem {
    bytes: FlatBytes,
    perms: PagePerms,
    dirty: DirtyPages,
    /// Every capture since the last reset ([`Memory::take_pages_since_reset`]).
    captured: Vec<core::ops::Range<u32>>,
    value_revision: u64,
}

/// Keep the established checked memory API while allowing native execution to
/// address the same bytes through its separately protected mapping.
#[derive(Debug)]
enum FlatBytes {
    Owned(Vec<u8>),
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    Native(crate::recompiler::memory::NativeMemory),
}

impl Default for FlatBytes {
    fn default() -> Self {
        Self::Owned(Vec::new())
    }
}

impl Clone for FlatBytes {
    fn clone(&self) -> Self {
        Self::Owned(self.to_vec())
    }
}

impl core::ops::Deref for FlatBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        match self {
            Self::Owned(bytes) => bytes,
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            Self::Native(bytes) => bytes,
        }
    }
}

impl FlatBytes {
    /// Base of the writable bytes. Every write through it must mark the
    /// written pages in the owning [`FlatMem`]'s dirty set.
    #[inline(always)]
    fn as_mut_ptr(&mut self) -> *mut u8 {
        match self {
            Self::Owned(bytes) => bytes.as_mut_ptr(),
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            Self::Native(bytes) => bytes.host_ptr(),
        }
    }

    fn clear_pages(&mut self, first: usize, count: usize) -> bool {
        match self {
            Self::Owned(bytes) => {
                bytes[first * PAGE..(first + count) * PAGE].fill(0);
                true
            }
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            Self::Native(bytes) => bytes.clear_pages(first, count),
        }
    }

    fn capacity(&self) -> usize {
        match self {
            Self::Owned(bytes) => bytes.capacity(),
            // As with the old lazily zeroed flat Vec, report reserved capacity,
            // not physical RSS; this is intentionally not an RSS estimator.
            #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
            Self::Native(bytes) => bytes.len(),
        }
    }
}

impl FlatMem {
    /// Wrap a buffer, zero-padding it to whole pages, with RW-everywhere
    /// default permissions (the kernel installs the real per-page map via
    /// [`Memory::set_page_perms`]).
    pub fn new(mut bytes: Vec<u8>) -> Self {
        let pages = bytes.len().div_ceil(PAGE);
        bytes.resize(pages * PAGE, 0);
        Self {
            bytes: FlatBytes::Owned(bytes),
            perms: PagePerms::new_rw(pages),
            dirty: DirtyPages::new(pages),
            captured: Vec::new(),
            value_revision: 0,
        }
    }

    #[inline(always)]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Read `N` bytes; `Err` carries the faulting page base.
    #[inline(always)]
    fn read<const N: usize>(&self, addr: u32) -> Result<[u8; N], u32> {
        if self.perms.readable(addr, N) {
            // SAFETY: readable() bounds-checks addr + N - 1 against the
            // page table, and `bytes` covers every page in it;
            // read_unaligned handles unaligned addresses.
            Ok(unsafe {
                core::ptr::read_unaligned(self.bytes.as_ptr().add(addr as usize).cast::<[u8; N]>())
            })
        } else {
            Err(self.perms.fault_page(addr, N, false))
        }
    }

    /// Write `N` bytes; `Err` carries the faulting page base.
    #[inline(always)]
    fn write<const N: usize>(&mut self, addr: u32, val: [u8; N]) -> Result<(), u32> {
        if self.perms.writable(addr, N) {
            // SAFETY: see read().
            unsafe {
                core::ptr::write_unaligned(
                    self.bytes.as_mut_ptr().add(addr as usize).cast::<[u8; N]>(),
                    val,
                );
            }
            self.dirty.mark_access(addr, N);
            self.value_revision = self
                .value_revision
                .checked_add(1)
                .expect("memory revision cannot wrap in one invocation");
            Ok(())
        } else {
            Err(self.perms.fault_page(addr, N, true))
        }
    }
}

/// Frame-table sentinel: the page has no frame yet and reads as zero.
const NO_FRAME: u32 = u32::MAX;

/// Guest page → frame index, as a two-level table: slots of 1,024 pages
/// whose leaves are allocated on the first frame in the slot. A 4 GiB span
/// costs one directory entry per slot until pages are touched.
#[derive(Clone, Debug, Default)]
struct FrameTable {
    leaves: Vec<Option<alloc::boxed::Box<[u32; SLOT_PAGES]>>>,
}

impl FrameTable {
    fn new(pages: usize) -> Self {
        Self {
            leaves: vec![None; pages.div_ceil(SLOT_PAGES)],
        }
    }

    /// The frame of `page`, or [`NO_FRAME`] when untouched or outside the
    /// span.
    #[inline(always)]
    fn get(&self, page: usize) -> u32 {
        match self.leaves.get(page / SLOT_PAGES) {
            Some(Some(leaf)) => leaf[page % SLOT_PAGES],
            _ => NO_FRAME,
        }
    }

    /// The frame of `page`, which must be inside the span.
    #[inline(always)]
    unsafe fn get_unchecked(&self, page: usize) -> u32 {
        // SAFETY: the caller bounds page by the span, which the directory
        // covers.
        match unsafe { self.leaves.get_unchecked(page / SLOT_PAGES) } {
            Some(leaf) => leaf[page % SLOT_PAGES],
            None => NO_FRAME,
        }
    }

    fn set(&mut self, page: usize, frame: u32) {
        self.leaves[page / SLOT_PAGES]
            .get_or_insert_with(|| alloc::boxed::Box::new([NO_FRAME; SLOT_PAGES]))
            [page % SLOT_PAGES] = frame;
    }

    fn allocated_bytes(&self) -> usize {
        self.leaves.capacity()
            * core::mem::size_of::<Option<alloc::boxed::Box<[u32; SLOT_PAGES]>>>()
            + self.leaves.iter().flatten().count() * SLOT_PAGES * core::mem::size_of::<u32>()
    }
}

/// Sparse guest memory: a page table over 4 KiB frames allocated on first
/// write. Semantically identical to a zero-initialized [`FlatMem`] of the
/// same span, but allocation is proportional to touched pages instead of
/// the address span.
#[derive(Clone, Debug, Default)]
pub struct SparseMem {
    /// Guest page → frame index into `frames`; [`NO_FRAME`] = untouched.
    table: FrameTable,
    /// Frame arena: frame `i` occupies `[i * 4096, (i + 1) * 4096)`.
    frames: Vec<u8>,
    /// Frame index → guest page. This inverse index makes canonical sparse
    /// snapshots proportional to allocated frames rather than the page
    /// table.
    frame_pages: Vec<u32>,
    perms: PagePerms,
    /// Per frame: written since the last capture. Only allocated frames can
    /// change, so this is the sparse form of the dirty set.
    frame_dirty: Vec<bool>,
    /// Pages written since the last capture, in first-write order.
    dirty: Vec<u32>,
    /// Every capture since the last reset ([`Memory::take_pages_since_reset`]).
    captured: Vec<core::ops::Range<u32>>,
    value_revision: u64,
}

impl SparseMem {
    /// Create sparse memory spanning `span` bytes (rounded up to whole
    /// pages), all pages RW like a fresh flat buffer, no frames allocated.
    pub fn new(span: u64) -> Self {
        assert!(span <= 1 << 32, "guest address space is 32-bit");
        let pages = span.div_ceil(PAGE as u64) as usize;
        Self {
            table: FrameTable::new(pages),
            frames: Vec::new(),
            frame_pages: Vec::new(),
            perms: PagePerms::new_rw(pages),
            frame_dirty: Vec::new(),
            dirty: Vec::new(),
            captured: Vec::new(),
            value_revision: 0,
        }
    }

    /// Arena offset of the page's frame for a write: allocates the frame on
    /// first touch and marks it dirty.
    #[inline(always)]
    fn write_frame(&mut self, page: usize) -> usize {
        let base = self.ensure_frame(page);
        let frame = base / PAGE;
        // SAFETY: `frame_dirty` has one entry per allocated frame.
        let dirty = unsafe { self.frame_dirty.get_unchecked_mut(frame) };
        if !*dirty {
            *dirty = true;
            self.dirty.push(page as u32);
        }
        base
    }

    /// The pages written since the last capture, as sorted, coalesced page
    /// ranges, clearing the marks.
    fn take_dirty(&mut self) -> Vec<core::ops::Range<u32>> {
        let mut pages = core::mem::take(&mut self.dirty);
        for &page in &pages {
            self.frame_dirty[self.table.get(page as usize) as usize] = false;
        }
        pages.sort_unstable();
        let mut ranges: Vec<core::ops::Range<u32>> = Vec::new();
        for page in pages {
            match ranges.last_mut() {
                Some(last) if last.end == page => last.end += 1,
                _ => ranges.push(page..page + 1),
            }
        }
        ranges
    }

    /// Arena offset of the page's frame, allocating a zeroed frame on
    /// first touch.
    fn ensure_frame(&mut self, page: usize) -> usize {
        let f = self.table.get(page);
        if f != NO_FRAME {
            return f as usize * PAGE;
        }
        let idx = self.frames.len() / PAGE;
        self.frames.resize(self.frames.len() + PAGE, 0);
        self.frame_pages.push(page as u32);
        self.frame_dirty.push(false);
        self.table.set(page, idx as u32);
        idx * PAGE
    }

    /// Read `N` bytes; `Err` carries the faulting page base.
    #[inline(always)]
    fn read<const N: usize>(&self, addr: u32) -> Result<[u8; N], u32> {
        if !self.perms.readable(addr, N) {
            return Err(self.perms.fault_page(addr, N, false));
        }
        let off = addr as usize & 0xFFF;
        if off + N <= PAGE {
            let page = (addr >> 12) as usize;
            // SAFETY: readable() bounds-checked the page against the
            // permission map, which covers the same span as the table.
            let f = unsafe { self.table.get_unchecked(page) };
            if f == NO_FRAME {
                return Ok([0; N]);
            }
            // SAFETY: frames are whole pages, so frame base + off + N is
            // within the arena; read_unaligned handles unaligned addresses.
            Ok(unsafe {
                core::ptr::read_unaligned(
                    self.frames
                        .as_ptr()
                        .add(f as usize * PAGE + off)
                        .cast::<[u8; N]>(),
                )
            })
        } else {
            Ok(self.read_straddle(addr))
        }
    }

    /// Byte-wise read across a page boundary (rare — max access width is
    /// 8 bytes, so at most two pages are involved).
    #[cold]
    fn read_straddle<const N: usize>(&self, addr: u32) -> [u8; N] {
        let mut out = [0u8; N];
        for (i, b) in out.iter_mut().enumerate() {
            // No wrap: the permission check bounds addr + N - 1 < 2³².
            let a = addr + i as u32;
            let f = self.table.get((a >> 12) as usize);
            if f != NO_FRAME {
                *b = self.frames[f as usize * PAGE + (a as usize & 0xFFF)];
            }
        }
        out
    }

    /// Write `N` bytes; `Err` carries the faulting page base.
    #[inline(always)]
    fn write<const N: usize>(&mut self, addr: u32, val: [u8; N]) -> Result<(), u32> {
        if !self.perms.writable(addr, N) {
            return Err(self.perms.fault_page(addr, N, true));
        }
        let off = addr as usize & 0xFFF;
        if off + N <= PAGE {
            let base = self.write_frame((addr >> 12) as usize) + off;
            // SAFETY: frames are whole pages, so base + N is within the
            // arena; write_unaligned handles unaligned addresses.
            unsafe {
                core::ptr::write_unaligned(
                    self.frames.as_mut_ptr().add(base).cast::<[u8; N]>(),
                    val,
                );
            }
        } else {
            self.write_straddle(addr, &val);
        }
        self.value_revision = self
            .value_revision
            .checked_add(1)
            .expect("memory revision cannot wrap in one invocation");
        Ok(())
    }

    /// Byte-wise write across a page boundary (rare; see read_straddle).
    #[cold]
    fn write_straddle(&mut self, addr: u32, val: &[u8]) {
        for (i, &b) in val.iter().enumerate() {
            let a = addr + i as u32;
            let base = self.write_frame((a >> 12) as usize) + (a as usize & 0xFFF);
            self.frames[base] = b;
        }
    }
}

/// Sort page ranges and merge those that overlap or touch.
fn coalesce(mut ranges: Vec<core::ops::Range<u32>>) -> Vec<core::ops::Range<u32>> {
    ranges.sort_unstable_by_key(|range| range.start);
    let mut merged: Vec<core::ops::Range<u32>> = Vec::with_capacity(ranges.len());
    for range in ranges {
        match merged.last_mut() {
            Some(last) if range.start <= last.end => last.end = last.end.max(range.end),
            _ => merged.push(range),
        }
    }
    merged
}

/// The interpreter's guest memory: flat (dense) or sparse (page table).
/// Constructor-selected; the representation never changes during a run.
#[derive(Clone, Debug)]
pub enum Memory {
    Flat(FlatMem),
    Sparse(SparseMem),
}

/// Dispatch a `&self` accessor to the active representation.
macro_rules! dispatch {
    ($self:expr, $m:ident => $body:expr) => {
        match $self {
            Memory::Flat($m) => $body,
            Memory::Sparse($m) => $body,
        }
    };
}

impl Memory {
    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn native(span: u64) -> Result<Self, alloc::string::String> {
        let bytes = crate::recompiler::memory::NativeMemory::new(span as usize)?;
        Ok(Self::Flat(FlatMem {
            bytes: FlatBytes::Native(bytes),
            perms: PagePerms::new_rw(span as usize / PAGE),
            dirty: DirtyPages::new(span as usize / PAGE),
            captured: Vec::new(),
            value_revision: 0,
        }))
    }

    #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
    pub(crate) fn native_window(
        &mut self,
    ) -> Result<
        (
            &crate::backing::CodeWindow,
            *const crate::recompiler::memory::Activation,
        ),
        alloc::string::String,
    > {
        let Self::Flat(memory) = self else {
            return Err("native execution requires native memory".into());
        };
        let FlatBytes::Native(bytes) = &mut memory.bytes else {
            return Err("native execution requires native memory".into());
        };
        bytes.sync_permissions(&mut memory.perms)?;
        // Native stores bypass checked host writes. Invalidate cached value
        // commitments at every execution boundary, including fault boundaries.
        memory.value_revision = memory
            .value_revision
            .checked_add(1)
            .expect("memory revision cannot wrap in one invocation");
        Ok((bytes.window(), bytes.activation()))
    }

    /// Flat memory over `bytes` (zero-padded to whole pages), all pages RW.
    pub fn flat(bytes: Vec<u8>) -> Self {
        Self::Flat(FlatMem::new(bytes))
    }

    /// Sparse memory spanning `span` bytes (rounded up to whole pages),
    /// all pages RW, reading as zero until written.
    pub fn sparse(span: u64) -> Self {
        Self::Sparse(SparseMem::new(span))
    }

    /// Number of 4 KiB pages in the guest span.
    pub fn pages(&self) -> usize {
        dispatch!(self, m => m.perms.pages())
    }

    /// Guest span in bytes (address 0 to the end of the highest page).
    pub fn span(&self) -> u64 {
        self.pages() as u64 * PAGE as u64
    }

    /// The permission of `page`, or `None` outside the span.
    pub fn page_perm(&self, page: usize) -> Option<u8> {
        dispatch!(self, m => (page < m.perms.pages()).then(|| m.perms.get(page)))
    }

    /// Whether every page of `[first, first + count)` is mapped (at least
    /// read-only). False when the range leaves the span.
    pub fn pages_mapped(&self, first: usize, count: usize) -> bool {
        first
            .checked_add(count)
            .is_some_and(|end| end <= self.pages())
            && dispatch!(self, m => m.perms.pages_have_at_least(first, first + count, super::PERM_RO))
    }

    /// The permission map as maximal runs `(first page, count, permission)`
    /// covering the span in order: the canonical form of the map, of size
    /// proportional to its permission changes rather than the span.
    pub fn permission_runs(&self) -> Vec<(usize, usize, u8)> {
        dispatch!(self, m => m.perms.runs())
    }

    /// The pages written since the last capture, by the guest or the host,
    /// as sorted, coalesced page ranges; the capture starts a new period.
    /// Every page whose contents changed is included. A page may also be
    /// included when a write left its contents unchanged.
    pub fn take_dirty_pages(&mut self) -> Vec<core::ops::Range<u32>> {
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        if let Memory::Flat(FlatMem {
            bytes: FlatBytes::Native(bytes),
            dirty,
            ..
        }) = self
        {
            // Guest stores through the native window. Once tracking has
            // failed, every page counts as written; a machine whose backend
            // failed must be dropped, never reused.
            if bytes
                .take_written(|first, count| dirty.mark_range(first, count))
                .is_err()
            {
                let (first, count) = bytes.span_pages();
                dirty.mark_range(first, count);
            }
        }
        let (pages, captured) = match self {
            Memory::Flat(m) => (m.dirty.take(), &mut m.captured),
            Memory::Sparse(m) => (m.take_dirty(), &mut m.captured),
        };
        captured.extend(pages.iter().cloned());
        if captured.len() > 4096 {
            *captured = coalesce(core::mem::take(captured));
        }
        pages
    }

    /// Every page written since the last call, whether or not a capture
    /// ([`Self::take_dirty_pages`]) has reported it since: what a pooled
    /// machine must restore. Starts a new capture period as well.
    pub(crate) fn take_pages_since_reset(&mut self) -> Vec<core::ops::Range<u32>> {
        self.take_dirty_pages();
        let captured = match self {
            Memory::Flat(m) => &mut m.captured,
            Memory::Sparse(m) => &mut m.captured,
        };
        coalesce(core::mem::take(captured))
    }

    /// The permission slots changed since the last call, with each slot's
    /// permission runs, for resetting a pooled machine.
    pub(crate) fn take_changed_permissions(&mut self) -> Vec<(usize, usize, u8)> {
        dispatch!(self, m => {
            let slots = m.perms.take_touched_slots();
            slots.into_iter().flat_map(|slot| m.perms.slot_runs(slot)).collect()
        })
    }

    /// Forget host writes made since the last capture, without asking the
    /// native window for guest writes: for a caller that wrote the memory
    /// itself, with no guest running since that capture.
    pub(crate) fn forget_host_writes(&mut self) {
        match self {
            Memory::Flat(m) => {
                m.dirty.take();
                m.captured.clear();
            }
            Memory::Sparse(m) => {
                m.take_dirty();
                m.captured.clear();
            }
        }
    }

    /// Set complete pages to zero by writing them, keeping their host
    /// memory: cheaper than [`Self::clear_pages`] for a few pages.
    pub(crate) fn zero_pages(&mut self, first: usize, count: usize) {
        assert!(
            first + count <= self.pages(),
            "zeroed pages exceed the span"
        );
        match self {
            Memory::Flat(m) => {
                // SAFETY: the assertion bounds the pages by the span, which
                // `bytes` covers.
                unsafe {
                    core::ptr::write_bytes(m.bytes.as_mut_ptr().add(first * PAGE), 0, count * PAGE);
                }
                m.dirty.mark_range(first, count);
            }
            Memory::Sparse(m) => {
                for page in first..first + count {
                    if m.table.get(page) != NO_FRAME {
                        let base = m.write_frame(page);
                        m.frames[base..base + PAGE].fill(0);
                    }
                }
            }
        }
        if count != 0 {
            dispatch!(self, m => {
                m.value_revision = m
                    .value_revision
                    .checked_add(1)
                    .expect("memory revision cannot wrap in one invocation");
            });
        }
    }

    /// Whether native write tracking has failed: the memory reports every
    /// page from then on, and must not be reused.
    pub(crate) fn tracking_failed(&self) -> bool {
        #[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
        if let Memory::Flat(FlatMem {
            bytes: FlatBytes::Native(bytes),
            ..
        }) = self
        {
            return bytes.tracking_failed();
        }
        false
    }

    /// Monotonic identity of the logical value image. Equal revisions for
    /// one memory object guarantee that no successful write/clear/init has
    /// occurred between observations.
    pub fn value_revision(&self) -> u64 {
        dispatch!(self, m => m.value_revision)
    }

    /// Monotonic identity of the page-permission map.
    pub fn permissions_revision(&self) -> u64 {
        dispatch!(self, m => m.perms.revision())
    }

    /// Install the per-page permission map. `perms` must have exactly one
    /// entry per 4 KiB page of the span — the accessors rely on the page
    /// bounds check doubling as the byte-range check.
    pub fn set_page_perms(&mut self, perms: Vec<u8>) {
        assert_eq!(
            perms.len(),
            self.pages(),
            "page_perms must cover guest memory exactly"
        );
        dispatch!(self, m => m.perms.install(perms));
    }

    /// Change the access mode of a page range without replacing the rest of
    /// the page table.
    ///
    /// The range must lie within the logical memory span. This is the
    /// primitive used by the standard inner-machine `pages` host call.
    pub fn set_page_range(&mut self, first: usize, count: usize, permission: u8) -> bool {
        let Some(end) = first.checked_add(count) else {
            return false;
        };
        if end > self.pages() {
            return false;
        }
        dispatch!(self, m => m.perms.set_range(first, count, permission));
        true
    }

    /// Reset complete pages to zero without allocating untouched sparse
    /// frames. Existing sparse frames are retained and cleared, so repeatedly
    /// recycling one page range cannot grow host memory.
    /// Native shared mappings discard backing pages instead of eagerly
    /// writing a zero-filled heap. Returns `false` for an invalid range or a
    /// failed native discard; callers must not continue execution on failure.
    pub fn clear_pages(&mut self, first: usize, count: usize) -> bool {
        let Some(end) = first.checked_add(count) else {
            return false;
        };
        if end > self.pages() {
            return false;
        }
        match self {
            Memory::Flat(m) => {
                if !m.bytes.clear_pages(first, count) {
                    return false;
                }
                m.dirty.mark_range(first, count);
                if count != 0 {
                    m.value_revision = m
                        .value_revision
                        .checked_add(1)
                        .expect("memory revision cannot wrap in one invocation");
                }
            }
            Memory::Sparse(m) => {
                // A page without a frame already reads as zero. Slots
                // without a leaf hold no frames and are skipped whole.
                let mut page = first;
                while page < end {
                    let slot_end = ((page / SLOT_PAGES + 1) * SLOT_PAGES).min(end);
                    if m.table.leaves[page / SLOT_PAGES].is_none() {
                        page = slot_end;
                        continue;
                    }
                    for page in page..slot_end {
                        if m.table.get(page) != NO_FRAME {
                            let base = m.write_frame(page);
                            m.frames[base..base + PAGE].fill(0);
                        }
                    }
                    page = slot_end;
                }
                if count != 0 {
                    m.value_revision = m
                        .value_revision
                        .checked_add(1)
                        .expect("memory revision cannot wrap in one invocation");
                }
            }
        }
        true
    }

    /// Whether the whole byte range is readable under the installed page
    /// map. Zero-length ranges are always accessible.
    #[cfg_attr(feature = "std", inline(always))]
    pub fn is_readable(&self, addr: u32, len: usize) -> bool {
        dispatch!(self, m => m.perms.range_has_at_least(addr, len, super::PERM_RO))
    }

    /// Whether the whole byte range is writable under the installed page
    /// map. Zero-length ranges are always accessible.
    #[cfg_attr(feature = "std", inline(always))]
    pub fn is_writable(&self, addr: u32, len: usize) -> bool {
        dispatch!(self, m => m.perms.range_has_at_least(addr, len, PERM_RW))
    }

    /// Copy a readable range into host memory.
    pub fn read_bytes_checked(&self, addr: u32, out: &mut [u8]) -> bool {
        if !self.is_readable(addr, out.len()) {
            return false;
        }
        self.read_bytes(addr, out);
        true
    }

    /// Copy host bytes into a writable range.
    pub fn write_bytes_checked(&mut self, addr: u32, data: &[u8]) -> bool {
        if !self.is_writable(addr, data.len()) {
            return false;
        }
        self.init_copy(addr, data);
        true
    }

    /// Read a byte; `Err` carries the faulting page base.
    #[inline(always)]
    pub fn read_u8(&self, addr: u32) -> Result<u8, u32> {
        dispatch!(self, m => m.read::<1>(addr).map(|b| b[0]))
    }

    #[inline(always)]
    pub fn read_u16_le(&self, addr: u32) -> Result<u16, u32> {
        dispatch!(self, m => m.read::<2>(addr).map(u16::from_le_bytes))
    }

    #[inline(always)]
    pub fn read_u32_le(&self, addr: u32) -> Result<u32, u32> {
        dispatch!(self, m => m.read::<4>(addr).map(u32::from_le_bytes))
    }

    #[inline(always)]
    pub fn read_u64_le(&self, addr: u32) -> Result<u64, u32> {
        dispatch!(self, m => m.read::<8>(addr).map(u64::from_le_bytes))
    }

    /// Write a byte; `Err` carries the faulting page base.
    #[inline(always)]
    pub fn write_u8(&mut self, addr: u32, val: u8) -> Result<(), u32> {
        dispatch!(self, m => m.write::<1>(addr, [val]))
    }

    #[inline(always)]
    pub fn write_u16_le(&mut self, addr: u32, val: u16) -> Result<(), u32> {
        dispatch!(self, m => m.write::<2>(addr, val.to_le_bytes()))
    }

    #[inline(always)]
    pub fn write_u32_le(&mut self, addr: u32, val: u32) -> Result<(), u32> {
        dispatch!(self, m => m.write::<4>(addr, val.to_le_bytes()))
    }

    #[inline(always)]
    pub fn write_u64_le(&mut self, addr: u32, val: u64) -> Result<(), u32> {
        dispatch!(self, m => m.write::<8>(addr, val.to_le_bytes()))
    }

    /// The flat backing buffer, or `None` under the sparse representation.
    pub fn as_flat(&self) -> Option<&[u8]> {
        match self {
            Memory::Flat(m) => Some(m.bytes()),
            Memory::Sparse(_) => None,
        }
    }

    /// Copy the logical memory image at `[addr, addr + buf.len())` into
    /// `buf`, ignoring permissions. Unmapped, untouched, or out-of-span
    /// bytes read as zero — exactly the flat image's content for pages
    /// never written. This is the representation-independent view used
    /// for output extraction and differential comparison.
    pub fn read_bytes(&self, addr: u32, buf: &mut [u8]) {
        match self {
            Memory::Flat(m) => {
                let a = addr as usize;
                let n = buf.len().min(m.bytes.len().saturating_sub(a));
                buf[..n].copy_from_slice(&m.bytes[a..a + n]);
                buf[n..].fill(0);
            }
            Memory::Sparse(m) => {
                let mut a = addr as u64;
                let mut buf = &mut buf[..];
                while !buf.is_empty() {
                    let off = (a % PAGE as u64) as usize;
                    let n = (PAGE - off).min(buf.len());
                    let page = (a / PAGE as u64) as usize;
                    match m.table.get(page) {
                        f if f != NO_FRAME => {
                            let base = f as usize * PAGE + off;
                            buf[..n].copy_from_slice(&m.frames[base..base + n]);
                        }
                        _ => buf[..n].fill(0),
                    }
                    a += n as u64;
                    buf = &mut buf[n..];
                }
            }
        }
    }

    /// Initialization write: copy `data` to `addr` ignoring permissions.
    /// Used to place ro/rw/args region contents before the permission map
    /// is installed. Panics if the range exceeds the span.
    pub fn init_copy(&mut self, addr: u32, data: &[u8]) {
        assert!(
            addr as u64 + data.len() as u64 <= self.span(),
            "init_copy range exceeds guest span"
        );
        let has_data = !data.is_empty();
        match self {
            Memory::Flat(m) => {
                // SAFETY: the assertion above bounds the range by the span,
                // which `bytes` covers; host data never aliases guest memory.
                unsafe {
                    core::ptr::copy_nonoverlapping(
                        data.as_ptr(),
                        m.bytes.as_mut_ptr().add(addr as usize),
                        data.len(),
                    );
                }
                if has_data {
                    let first = addr as usize / PAGE;
                    let last = (addr as usize + data.len() - 1) / PAGE;
                    m.dirty.mark_range(first, last - first + 1);
                    m.value_revision = m
                        .value_revision
                        .checked_add(1)
                        .expect("memory revision cannot wrap in one invocation");
                }
            }
            Memory::Sparse(m) => {
                let mut a = addr as u64;
                let mut data = data;
                while !data.is_empty() {
                    let off = (a % PAGE as u64) as usize;
                    let n = (PAGE - off).min(data.len());
                    let base = m.write_frame((a / PAGE as u64) as usize) + off;
                    m.frames[base..base + n].copy_from_slice(&data[..n]);
                    a += n as u64;
                    data = &data[n..];
                }
                if has_data {
                    m.value_revision = m
                        .value_revision
                        .checked_add(1)
                        .expect("memory revision cannot wrap in one invocation");
                }
            }
        }
    }

    /// Host bytes actually allocated for this memory (buffer/table/arena
    /// capacities plus the permission map). For sparse memory this is
    /// O(touched pages) + the fixed tables, independent of the guest span
    /// — the property that makes 4 GiB layouts viable on 32-bit hosts.
    pub fn allocated_bytes(&self) -> usize {
        match self {
            Memory::Flat(m) => {
                m.bytes.capacity() + m.perms.allocated_bytes() + m.dirty.allocated_bytes()
            }
            Memory::Sparse(m) => {
                m.table.allocated_bytes()
                    + m.frames.capacity()
                    + m.frame_pages.capacity() * core::mem::size_of::<u32>()
                    + m.perms.allocated_bytes()
                    + m.frame_dirty.capacity()
                    + m.dirty.capacity() * core::mem::size_of::<u32>()
            }
        }
    }

    /// Whether this memory uses the sparse representation.
    pub fn is_sparse(&self) -> bool {
        matches!(self, Self::Sparse(_))
    }

    /// Snapshot the logical value image as sorted non-zero pages.
    ///
    /// The result is representation-independent: equal flat and sparse
    /// memories produce byte-identical page sequences. Runtime proof tracing
    /// forces sparse execution, so this remains O(touched pages) rather than
    /// scanning or allocating the full 32-bit address space.
    pub fn nonzero_page_image(&self) -> SparseMemoryImage {
        let mut pages = Vec::new();
        match self {
            Memory::Flat(memory) => {
                for (page_index, chunk) in memory.bytes.chunks(PAGE).enumerate() {
                    if chunk.iter().all(|&byte| byte == 0) {
                        continue;
                    }
                    let mut bytes = [0; PAGE];
                    bytes[..chunk.len()].copy_from_slice(chunk);
                    pages.push(NonZeroPage {
                        page_index: page_index as u32,
                        bytes,
                    });
                }
            }
            Memory::Sparse(memory) => {
                for (frame, &page_index) in memory.frame_pages.iter().enumerate() {
                    let base = frame * PAGE;
                    let frame = &memory.frames[base..base + PAGE];
                    if frame.iter().all(|&byte| byte == 0) {
                        continue;
                    }
                    let mut bytes = [0; PAGE];
                    bytes.copy_from_slice(frame);
                    pages.push(NonZeroPage { page_index, bytes });
                }
                pages.sort_unstable_by_key(|page| page.page_index);
            }
        }
        SparseMemoryImage {
            span: self.span(),
            pages,
        }
    }
}

impl Default for Memory {
    fn default() -> Self {
        Self::Flat(FlatMem::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interpreter::PERM_RO;
    use proptest::prelude::*;

    /// Flat and sparse memories with the same 6-page layout:
    /// pages 0-1 RW, page 2 NONE (gap), page 3 RO, pages 4-5 RW.
    fn pair() -> (Memory, Memory) {
        let perms = vec![PERM_RW, PERM_RW, PERM_NONE, PERM_RO, PERM_RW, PERM_RW];
        let mut flat = Memory::flat(vec![0u8; 6 * PAGE]);
        let mut sparse = Memory::sparse(6 * PAGE as u64);
        // RO content must be placed before the permission map lands.
        let ro_data: Vec<u8> = (0..64).map(|i| i as u8 ^ 0x5A).collect();
        flat.init_copy(3 * PAGE as u32, &ro_data);
        sparse.init_copy(3 * PAGE as u32, &ro_data);
        flat.set_page_perms(perms.clone());
        sparse.set_page_perms(perms);
        (flat, sparse)
    }

    #[test]
    fn untouched_pages_read_zero_in_both() {
        let (flat, sparse) = pair();
        for addr in [0u32, 5, 4096, 8184, 5 * PAGE as u32 + 4088] {
            assert_eq!(flat.read_u64_le(addr), Ok(0), "flat @{addr:#x}");
            assert_eq!(sparse.read_u64_le(addr), Ok(0), "sparse @{addr:#x}");
        }
    }

    #[test]
    fn mutation_revisions_change_only_the_relevant_state_class() {
        for mut memory in [Memory::flat(vec![0; PAGE]), Memory::sparse(PAGE as u64)] {
            let values = memory.value_revision();
            let permissions = memory.permissions_revision();
            memory.write_u8(0, 7).unwrap();
            assert_eq!(memory.value_revision(), values + 1);
            assert_eq!(memory.permissions_revision(), permissions);

            let values = memory.value_revision();
            assert!(memory.set_page_range(0, 1, PERM_RO));
            assert_eq!(memory.value_revision(), values);
            assert_eq!(memory.permissions_revision(), permissions + 1);

            // Idempotent permission installs do not invalidate a cached hash.
            assert!(memory.set_page_range(0, 1, PERM_RO));
            assert_eq!(memory.permissions_revision(), permissions + 1);
        }
    }

    #[test]
    fn nonzero_page_image_is_canonical_and_handles_high_addresses() {
        let mut memory = Memory::sparse(1u64 << 32);
        let address = u32::MAX - 31;
        // Allocate out of guest-page order: snapshots must still canonicalize.
        memory.init_copy(address, b"high-page");
        memory.init_copy(2 * PVM_PAGE_SIZE, b"low-page");
        let image = memory.nonzero_page_image();

        assert_eq!(image.span(), 1u64 << 32);
        assert_eq!(image.pages().len(), 2);
        assert_eq!(image.pages()[0].page_index, 2);
        assert_eq!(image.pages()[1].page_index, address / PVM_PAGE_SIZE);
        assert_eq!(image.byte(address), b'h');
        assert_eq!(image.byte(address + 8), b'e');
        assert!(memory.allocated_bytes() < 64 << 10);

        let cloned = memory.clone();
        assert_eq!(cloned.nonzero_page_image(), image);
        let Memory::Sparse(sparse) = &memory else {
            unreachable!()
        };
        assert_eq!(sparse.frame_pages, [address / PVM_PAGE_SIZE, 2]);
        assert_eq!(sparse.frames.len(), 2 * PAGE);
        for (frame, &page) in sparse.frame_pages.iter().enumerate() {
            assert_eq!(sparse.table.get(page as usize), frame as u32);
        }
        assert_eq!(
            memory.allocated_bytes(),
            sparse.table.allocated_bytes()
                + sparse.frames.capacity()
                + sparse.frame_pages.capacity() * core::mem::size_of::<u32>()
                + sparse.perms.allocated_bytes()
                + sparse.frame_dirty.capacity()
                + sparse.dirty.capacity() * core::mem::size_of::<u32>()
        );
        let empty = SparseMem::default();
        assert!(empty.table.leaves.is_empty());
        assert!(empty.frames.is_empty());
        assert!(empty.frame_pages.is_empty());

        let mut updated = image.clone();
        assert!(updated.write(address, &[0; 9]));
        assert_eq!(updated.pages().len(), 1, "zero pages are removed");
        assert!(!updated.write(u32::MAX - 3, &[1; 5]));
        assert!(SparseMemoryImage::new(1u64 << 32, image.pages().to_vec()).is_some());
        assert!(SparseMemoryImage::new(1u64 << 32, vec![image.pages()[0].clone(); 2]).is_none());
    }

    #[test]
    fn straddling_write_and_read_agree() {
        let (mut flat, mut sparse) = pair();
        // Straddles pages 0 and 1 (both RW).
        let addr = PAGE as u32 - 3;
        for m in [&mut flat, &mut sparse] {
            m.write_u64_le(addr, 0x1122334455667788).unwrap();
        }
        assert_eq!(flat.read_u64_le(addr), sparse.read_u64_le(addr));
        assert_eq!(flat.read_u32_le(addr + 2), sparse.read_u32_le(addr + 2));
        // The sparse arena has exactly the touched frames: the RO init
        // frame from pair() plus the two pages this write straddled.
        let Memory::Sparse(s) = &sparse else {
            unreachable!()
        };
        assert_eq!(s.frames.len(), 3 * PAGE);
    }

    #[test]
    fn straddle_into_unmapped_page_faults_at_its_base() {
        let (mut flat, mut sparse) = pair();
        // Page 1 is RW but page 2 is unmapped: a wide access at the
        // boundary reports page 2's base — in both representations.
        let addr = 2 * PAGE as u32 - 4;
        assert_eq!(flat.read_u64_le(addr), Err(2 * PAGE as u32));
        assert_eq!(sparse.read_u64_le(addr), Err(2 * PAGE as u32));
        assert_eq!(flat.write_u64_le(addr, 1), Err(2 * PAGE as u32));
        assert_eq!(sparse.write_u64_le(addr, 1), Err(2 * PAGE as u32));
    }

    #[test]
    fn read_only_and_unmapped_permissions_agree() {
        let (mut flat, mut sparse) = pair();
        let ro = 3 * PAGE as u32;
        let none = 2 * PAGE as u32 + 8;
        for m in [&mut flat, &mut sparse] {
            // RO: readable (the init data is visible), not writable.
            assert_eq!(m.read_u8(ro), Ok(0x5A));
            assert_eq!(m.write_u8(ro, 1), Err(ro));
            // NONE: neither.
            assert_eq!(m.read_u8(none), Err(2 * PAGE as u32));
            assert_eq!(m.write_u8(none, 1), Err(2 * PAGE as u32));
            // Out of span: fault at the (unmapped) page base.
            assert_eq!(m.read_u8(6 * PAGE as u32), Err(6 * PAGE as u32));
        }
    }

    #[test]
    fn logical_image_matches_after_identical_writes() {
        let (mut flat, mut sparse) = pair();
        for m in [&mut flat, &mut sparse] {
            m.write_u32_le(100, 0xAABBCCDD).unwrap();
            m.write_u64_le(PAGE as u32 - 5, 0x0102030405060708).unwrap();
            m.write_u8(4 * PAGE as u32, 0xEE).unwrap();
        }
        let mut bf = vec![0u8; 6 * PAGE];
        let mut bs = vec![0u8; 6 * PAGE];
        flat.read_bytes(0, &mut bf);
        sparse.read_bytes(0, &mut bs);
        assert_eq!(bf, bs, "full logical images agree");
    }

    #[test]
    fn sparse_allocation_is_bounded_by_touched_pages() {
        // A near-full 32-bit span: the flat form would be ~4 GiB.
        let span = (1u64 << 32) - (1 << 16);
        let mut m = Memory::sparse(span);
        assert!(m.span() >= span);
        // Touch one low and one high page (the two GP clusters).
        m.write_u64_le(0x2_0000, 1).unwrap();
        m.write_u64_le((span - 8) as u32, 2).unwrap();
        assert_eq!(m.read_u64_le(0x2_0000), Ok(1));
        assert_eq!(m.read_u64_le((span - 8) as u32), Ok(2));
        // Two directories, two frame-table leaves and two frames, where
        // flat needs ~4 GiB.
        assert!(
            m.allocated_bytes() < 64 << 10,
            "allocated {} bytes",
            m.allocated_bytes()
        );
    }

    #[test]
    fn permission_slots_stay_uniform_when_whole_slots_change() {
        let pages = 3 * SLOT_PAGES + 7;
        let mut memory = Memory::sparse((pages * PAGE) as u64);
        assert!(memory.set_page_range(0, pages, PERM_NONE));
        assert!(memory.set_page_range(SLOT_PAGES + 3, 2, PERM_RO));
        let Memory::Sparse(sparse) = &memory else {
            unreachable!()
        };
        let mixed = |perms: &PagePerms| {
            perms
                .slots
                .iter()
                .filter(|slot| matches!(slot, PermSlot::Mixed(_)))
                .count()
        };
        assert_eq!(mixed(&sparse.perms), 1);
        assert_eq!(
            memory.permission_runs(),
            [
                (0, SLOT_PAGES + 3, PERM_NONE),
                (SLOT_PAGES + 3, 2, PERM_RO),
                (SLOT_PAGES + 5, pages - SLOT_PAGES - 5, PERM_NONE),
            ]
        );
        // Restoring the slot collapses its leaf again.
        assert!(memory.set_page_range(SLOT_PAGES + 3, 2, PERM_NONE));
        let Memory::Sparse(sparse) = &memory else {
            unreachable!()
        };
        assert_eq!(mixed(&sparse.perms), 0);
        assert_eq!(memory.permission_runs(), [(0, pages, PERM_NONE)]);
        assert_eq!(memory.page_perm(pages - 1), Some(PERM_NONE));
        assert_eq!(memory.page_perm(pages), None);
    }

    fn pages_of(ranges: &[core::ops::Range<u32>]) -> Vec<u32> {
        ranges.iter().cloned().flatten().collect()
    }

    #[test]
    fn dirty_pages_cover_guest_and_host_writes() {
        let (mut flat, mut sparse) = pair();
        for memory in [&mut flat, &mut sparse] {
            assert_eq!(pages_of(&memory.take_dirty_pages()), [3], "layout copy");
            assert!(memory.take_dirty_pages().is_empty(), "capture clears");
            memory.write_u8(5, 1).unwrap();
            memory.write_u64_le(2 * PAGE as u32 - 4, 7).unwrap_err();
            memory.write_u64_le(PAGE as u32 - 4, 7).unwrap();
            assert!(memory.write_bytes_checked(4 * PAGE as u32 + 9, &[1; 4096]));
            assert_eq!(memory.take_dirty_pages(), [0..2, 4..6]);
            // A failed write marks nothing.
            assert!(!memory.write_bytes_checked(3 * PAGE as u32, &[1]));
            assert!(memory.take_dirty_pages().is_empty());
        }
    }

    #[test]
    fn clearing_marks_only_what_can_change() {
        let pages = 3 * SLOT_PAGES + 5;
        let mut flat = Memory::flat(vec![0; pages * PAGE]);
        let mut sparse = Memory::sparse((pages * PAGE) as u64);
        for memory in [&mut flat, &mut sparse] {
            memory
                .write_u8((SLOT_PAGES as u32 + 7) * PAGE as u32, 1)
                .unwrap();
            memory.take_dirty_pages();
            assert!(memory.clear_pages(1, pages - 1));
        }
        // Flat memory marks the whole range, whole slots in one step; sparse
        // memory marks only pages that hold a frame.
        assert_eq!(
            pages_of(&flat.take_dirty_pages()),
            (1..pages as u32).collect::<Vec<_>>()
        );
        assert_eq!(
            pages_of(&sparse.take_dirty_pages()),
            [SLOT_PAGES as u32 + 7]
        );
        let Memory::Flat(flat) = &flat else {
            unreachable!()
        };
        assert!(flat.dirty.allocated_bytes() < 64 << 10);
    }

    fn permission() -> impl Strategy<Value = u8> {
        prop_oneof![Just(PERM_NONE), Just(PERM_RO), Just(PERM_RW)]
    }

    proptest! {
        /// The two-level permission map behaves exactly like one entry per
        /// page: lookups, access checks, fault pages and canonical runs.
        #[test]
        fn permission_map_matches_a_flat_model(
            pages in 1usize..3 * SLOT_PAGES,
            ops in proptest::collection::vec(
                (0usize..3 * SLOT_PAGES, 0usize..2 * SLOT_PAGES, permission()),
                1..12,
            ),
            probes in proptest::collection::vec((any::<u32>(), 0usize..9), 32),
        ) {
            let mut perms = PagePerms::new_rw(pages);
            let mut model = vec![PERM_RW; pages];
            for (first, count, permission) in ops {
                let first = first % pages;
                let count = count.min(pages - first);
                perms.set_range(first, count, permission);
                model[first..first + count].fill(permission);
                prop_assert_eq!(perms.uniform_rw, model.iter().all(|&p| p == PERM_RW));
            }
            for (page, &permission) in model.iter().enumerate() {
                prop_assert_eq!(perms.get(page), permission);
            }
            let mut expected: Vec<(usize, usize, u8)> = Vec::new();
            for (page, &permission) in model.iter().enumerate() {
                match expected.last_mut() {
                    Some((_, count, last)) if *last == permission => *count += 1,
                    _ => expected.push((page, 1, permission)),
                }
            }
            prop_assert_eq!(perms.runs(), expected);

            let span = (pages * PAGE) as u64;
            for (addr, len) in probes {
                let addr = (addr as u64 % (span + 2 * PAGE as u64)).min(u32::MAX as u64) as u32;
                let covered = |minimum: u8| {
                    len == 0
                        || (addr as u64 + len as u64 <= span
                            && (addr as usize / PAGE..=(addr as usize + len - 1) / PAGE)
                                .all(|page| model[page] >= minimum))
                };
                prop_assert_eq!(perms.range_has_at_least(addr, len, PERM_RO), covered(PERM_RO));
                prop_assert_eq!(perms.range_has_at_least(addr, len, PERM_RW), covered(PERM_RW));
                if len > 0 {
                    prop_assert_eq!(perms.readable(addr, len), covered(PERM_RO));
                    prop_assert_eq!(perms.writable(addr, len), covered(PERM_RW));
                }
            }
        }

        /// Every page whose contents changed since the last capture is in
        /// the next capture, and so is every page a write succeeded on.
        #[test]
        fn dirty_pages_cover_every_change(
            rounds in proptest::collection::vec(
                proptest::collection::vec(
                    (0u32..7 * PAGE as u32, 0u8..6, any::<u64>(), 0usize..3 * PAGE),
                    1..24,
                ),
                1..4,
            )
        ) {
            let (mut flat, mut sparse) = pair();
            for memory in [&mut flat, &mut sparse] {
                memory.take_dirty_pages();
                let image = |memory: &Memory| {
                    let mut bytes = vec![0u8; 6 * PAGE];
                    memory.read_bytes(0, &mut bytes);
                    bytes
                };
                for ops in &rounds {
                    let before = image(memory);
                    let mut written = alloc::collections::BTreeSet::new();
                    for &(addr, op, value, len) in ops {
                        let touched = |addr: u32, len: usize| {
                            (addr / PAGE as u32..=(addr + len as u32 - 1) / PAGE as u32)
                                .collect::<Vec<_>>()
                        };
                        let ok = match op {
                            0 => memory.write_u8(addr, value as u8).is_ok(),
                            1 => memory.write_u64_le(addr, value).is_ok(),
                            2 => memory.write_bytes_checked(addr, &vec![value as u8; len.max(1)]),
                            3 => memory.clear_pages(addr as usize / PAGE, len / PAGE),
                            _ => {
                                memory.set_page_range(addr as usize / PAGE % 6, 1, value as u8 % 3);
                                false
                            }
                        };
                        if ok && op < 3 {
                            let width = [1, 8, len.max(1)][op as usize];
                            written.extend(touched(addr, width));
                        }
                    }
                    let after = image(memory);
                    let dirty = pages_of(&memory.take_dirty_pages());
                    for page in 0..6u32 {
                        let range = page as usize * PAGE..(page as usize + 1) * PAGE;
                        if before[range.clone()] != after[range] || written.contains(&page) {
                            prop_assert!(dirty.contains(&page), "page {} missed", page);
                        }
                    }
                }
            }
        }

        /// Differential fuzz: any sequence of reads/writes of any width
        /// behaves identically on flat and sparse memory — results,
        /// values, and fault addresses.
        #[test]
        fn flat_and_sparse_are_indistinguishable(
            ops in proptest::collection::vec(
                (0u32..7 * PAGE as u32, 0u8..4, any::<bool>(), any::<u64>()),
                1..64,
            )
        ) {
            let (mut flat, mut sparse) = pair();
            for (addr, width, is_write, val) in ops {
                if is_write {
                    let (a, b) = match width {
                        0 => (flat.write_u8(addr, val as u8), sparse.write_u8(addr, val as u8)),
                        1 => (flat.write_u16_le(addr, val as u16), sparse.write_u16_le(addr, val as u16)),
                        2 => (flat.write_u32_le(addr, val as u32), sparse.write_u32_le(addr, val as u32)),
                        _ => (flat.write_u64_le(addr, val), sparse.write_u64_le(addr, val)),
                    };
                    prop_assert_eq!(a, b, "write w{} @{:#x}", width, addr);
                } else {
                    let (a, b) = match width {
                        0 => (flat.read_u8(addr).map(u64::from), sparse.read_u8(addr).map(u64::from)),
                        1 => (flat.read_u16_le(addr).map(u64::from), sparse.read_u16_le(addr).map(u64::from)),
                        2 => (flat.read_u32_le(addr).map(u64::from), sparse.read_u32_le(addr).map(u64::from)),
                        _ => (flat.read_u64_le(addr), sparse.read_u64_le(addr)),
                    };
                    prop_assert_eq!(a, b, "read w{} @{:#x}", width, addr);
                }
            }
            let mut bf = vec![0u8; 6 * PAGE];
            let mut bs = vec![0u8; 6 * PAGE];
            flat.read_bytes(0, &mut bf);
            sparse.read_bytes(0, &mut bs);
            prop_assert_eq!(bf, bs, "logical images diverged");
        }
    }
}
