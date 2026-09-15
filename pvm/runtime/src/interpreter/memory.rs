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
/// commit complete architectural state must bind [`Memory::page_perms`]
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

/// Per-page access map shared by both memory representations.
///
/// Mirrors the recompiler's hardware page protection (PROT_NONE /
/// PROT_READ / PROT_READ|WRITE): reads need at least [`super::PERM_RO`],
/// writes need [`PERM_RW`], and any access touching an unmapped page
/// faults. Failures report the offending page base — GP page faults are
/// page-granular, matching the Lean oracle and the JIT's SIGSEGV path.
///
/// All address arithmetic is done in `u64`: `addr + n - 1` may exceed
/// `u32::MAX` for a wide access at the top of the address space, and on
/// 32-bit hosts a `usize` sum would wrap and defeat the bounds check.
#[derive(Clone, Debug, Default)]
pub struct PagePerms {
    perms: Vec<u8>,
    /// True when every page is [`PERM_RW`]. In that (common) case a
    /// mapped-page bounds check subsumes the permission check, so the
    /// accessors skip the per-page table load — the flat-buffer fast path
    /// for programs with no read-only or unmapped pages.
    uniform_rw: bool,
    /// Monotonic mutation counter used by proof observers to cache the
    /// canonical permission commitment without rescanning the page table at
    /// every host boundary.
    revision: u64,
}

impl PagePerms {
    fn new_rw(pages: usize) -> Self {
        Self {
            perms: vec![PERM_RW; pages],
            uniform_rw: true,
            revision: 0,
        }
    }

    fn install(&mut self, perms: Vec<u8>) {
        if self.perms == perms {
            return;
        }
        self.uniform_rw = perms.iter().all(|&p| p == PERM_RW);
        self.perms = perms;
        self.revision = self
            .revision
            .checked_add(1)
            .expect("permission revision cannot wrap in one invocation");
    }

    #[inline(always)]
    fn pages(&self) -> usize {
        self.perms.len()
    }

    #[inline(always)]
    fn as_slice(&self) -> &[u8] {
        &self.perms
    }

    #[inline(always)]
    fn revision(&self) -> u64 {
        self.revision
    }

    fn set_range(&mut self, first: usize, count: usize, permission: u8) {
        if self.perms[first..first + count]
            .iter()
            .all(|&existing| existing == permission)
        {
            return;
        }
        self.perms[first..first + count].fill(permission);
        self.uniform_rw = self.perms.iter().all(|&p| p == PERM_RW);
        self.revision = self
            .revision
            .checked_add(1)
            .expect("permission revision cannot wrap in one invocation");
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
        if end > self.perms.len() as u64 * PAGE as u64 {
            return false;
        }
        let first = (addr as usize) / PAGE;
        let last = ((end - 1) as usize) / PAGE;
        self.perms[first..=last].iter().all(|&p| p >= permission)
    }

    /// True when the last byte of `[addr, addr+n)` is on a mapped page
    /// (bounds check). Under uniform-RW memory this subsumes both
    /// readable/writable.
    #[inline(always)]
    fn in_bounds(&self, addr: u32, n: usize) -> bool {
        ((addr as u64 + n as u64 - 1) >> 12) < self.perms.len() as u64
    }

    /// True when `[addr, addr+n)` is entirely on readable pages.
    #[inline(always)]
    fn readable(&self, addr: u32, n: usize) -> bool {
        if self.uniform_rw {
            return self.in_bounds(addr, n);
        }
        let page = (addr >> 12) as usize;
        if page >= self.perms.len() {
            return false;
        }
        // SAFETY: page < perms.len().
        if unsafe { *self.perms.get_unchecked(page) } == PERM_NONE {
            return false;
        }
        if (addr as usize & 0xFFF) + n > PAGE {
            let last = page + 1;
            // SAFETY: bounds-checked before the load.
            return last < self.perms.len()
                && unsafe { *self.perms.get_unchecked(last) } != PERM_NONE;
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
        if page >= self.perms.len() {
            return false;
        }
        // SAFETY: page < perms.len().
        if unsafe { *self.perms.get_unchecked(page) } != PERM_RW {
            return false;
        }
        if (addr as usize & 0xFFF) + n > PAGE {
            let last = page + 1;
            // SAFETY: bounds-checked before the load.
            return last < self.perms.len()
                && unsafe { *self.perms.get_unchecked(last) } == PERM_RW;
        }
        true
    }

    /// Page base of the first page in `[addr, addr+n)` that fails the
    /// access check. Only called after a failed access (cold path).
    #[cold]
    fn fault_page(&self, addr: u32, n: usize, write: bool) -> u32 {
        let ok = |p: u64| {
            (p as usize) < self.perms.len()
                && if write {
                    self.perms[p as usize] == PERM_RW
                } else {
                    self.perms[p as usize] != PERM_NONE
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
        self.perms.capacity()
    }
}

/// Dense guest memory: one buffer spanning address 0 to the end of the
/// highest mapped page. Always a whole number of 4 KiB pages; the
/// permission map has exactly one entry per page, so the page-index bounds
/// check doubles as the byte-range check.
#[derive(Clone, Debug, Default)]
pub struct FlatMem {
    bytes: Vec<u8>,
    perms: PagePerms,
    value_revision: u64,
}

impl FlatMem {
    /// Wrap a buffer, zero-padding it to whole pages, with RW-everywhere
    /// default permissions (the kernel installs the real per-page map via
    /// [`Memory::set_page_perms`]).
    pub fn new(mut bytes: Vec<u8>) -> Self {
        let pages = bytes.len().div_ceil(PAGE);
        bytes.resize(pages * PAGE, 0);
        Self {
            bytes,
            perms: PagePerms::new_rw(pages),
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

/// Sparse guest memory: a page table over 4 KiB frames allocated on first
/// write. Semantically identical to a zero-initialized [`FlatMem`] of the
/// same span, but allocation is proportional to touched pages instead of
/// the address span.
#[derive(Clone, Debug, Default)]
pub struct SparseMem {
    /// Guest page → frame index into `frames`; [`NO_FRAME`] = untouched.
    table: Vec<u32>,
    /// Frame arena: frame `i` occupies `[i * 4096, (i + 1) * 4096)`.
    frames: Vec<u8>,
    /// Frame index → guest page. This inverse index makes canonical sparse
    /// snapshots proportional to allocated frames rather than the complete
    /// million-entry 32-bit page table.
    frame_pages: Vec<u32>,
    perms: PagePerms,
    value_revision: u64,
}

impl SparseMem {
    /// Create sparse memory spanning `span` bytes (rounded up to whole
    /// pages), all pages RW like a fresh flat buffer, no frames allocated.
    pub fn new(span: u64) -> Self {
        assert!(span <= 1 << 32, "guest address space is 32-bit");
        let pages = span.div_ceil(PAGE as u64) as usize;
        Self {
            table: vec![NO_FRAME; pages],
            frames: Vec::new(),
            frame_pages: Vec::new(),
            perms: PagePerms::new_rw(pages),
            value_revision: 0,
        }
    }

    /// Arena offset of the page's frame, allocating a zeroed frame on
    /// first touch.
    fn ensure_frame(&mut self, page: usize) -> usize {
        let f = self.table[page];
        if f != NO_FRAME {
            return f as usize * PAGE;
        }
        let idx = self.frames.len() / PAGE;
        self.frames.resize(self.frames.len() + PAGE, 0);
        self.frame_pages.push(page as u32);
        self.table[page] = idx as u32;
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
            // permission map, which covers exactly `table.len()` pages.
            let f = unsafe { *self.table.get_unchecked(page) };
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
            let f = self.table[(a >> 12) as usize];
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
            let base = self.ensure_frame((addr >> 12) as usize) + off;
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
            let base = self.ensure_frame((a >> 12) as usize) + (a as usize & 0xFFF);
            self.frames[base] = b;
        }
    }
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

    /// The per-page permission map (one `PERM_*` entry per page).
    pub fn page_perms(&self) -> &[u8] {
        dispatch!(self, m => m.perms.as_slice())
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
    pub fn clear_pages(&mut self, first: usize, count: usize) -> bool {
        let Some(end) = first.checked_add(count) else {
            return false;
        };
        if end > self.pages() {
            return false;
        }
        match self {
            Memory::Flat(m) => {
                m.bytes[first * PAGE..end * PAGE].fill(0);
                if count != 0 {
                    m.value_revision = m
                        .value_revision
                        .checked_add(1)
                        .expect("memory revision cannot wrap in one invocation");
                }
            }
            Memory::Sparse(m) => {
                for page in first..end {
                    let frame = m.table[page];
                    if frame != NO_FRAME {
                        let base = frame as usize * PAGE;
                        m.frames[base..base + PAGE].fill(0);
                    }
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
                        Some(&f) if f != NO_FRAME => {
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
                m.bytes[addr as usize..addr as usize + data.len()].copy_from_slice(data);
                if has_data {
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
                    let base = m.ensure_frame((a / PAGE as u64) as usize) + off;
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
            Memory::Flat(m) => m.bytes.capacity() + m.perms.allocated_bytes(),
            Memory::Sparse(m) => {
                m.table.capacity() * core::mem::size_of::<u32>()
                    + m.frames.capacity()
                    + m.frame_pages.capacity() * core::mem::size_of::<u32>()
                    + m.perms.allocated_bytes()
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
        assert!(memory.allocated_bytes() < 16 << 20);

        let cloned = memory.clone();
        assert_eq!(cloned.nonzero_page_image(), image);
        let Memory::Sparse(sparse) = &memory else {
            unreachable!()
        };
        assert_eq!(sparse.frame_pages, [address / PVM_PAGE_SIZE, 2]);
        assert_eq!(sparse.frames.len(), 2 * PAGE);
        for (frame, &page) in sparse.frame_pages.iter().enumerate() {
            assert_eq!(sparse.table[page as usize], frame as u32);
        }
        assert_eq!(
            memory.allocated_bytes(),
            sparse.table.capacity() * core::mem::size_of::<u32>()
                + sparse.frames.capacity()
                + sparse.frame_pages.capacity() * core::mem::size_of::<u32>()
                + sparse.perms.allocated_bytes()
        );
        let empty = SparseMem::default();
        assert!(empty.table.is_empty());
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
        // Page table (4 MiB) + perms (1 MiB) + two frames — well under
        // 16 MiB where flat needs ~4 GiB.
        assert!(
            m.allocated_bytes() < 16 << 20,
            "allocated {} bytes",
            m.allocated_bytes()
        );
    }

    proptest! {
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
