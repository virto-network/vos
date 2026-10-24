//! The pages a program may touch, and how: four regions of whole pages,
//! the first [`FIRST_WRITABLE`] readable, the rest writable, which
//! MemoryPageChip's preprocessed region columns hold, so part of the
//! program's identity.

/// A layout's regions: the first [`FIRST_WRITABLE`] readable, the rest
/// writable.
pub const REGIONS: usize = 4;
pub const FIRST_WRITABLE: usize = 2;

/// The pages a program may touch, and how. Four regions of whole pages: the
/// read-only data and the argument window, readable; the read-write data
/// with its heap and the stack, writable. Every other page is unmapped.
#[cfg(feature = "prover")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryLayout {
    pub regions: [PageRange; REGIONS],
}

/// The pages `[first, end)`.
#[cfg(feature = "prover")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PageRange {
    pub first: u32,
    pub end: u32,
}

/// What a page allows, as the ledger's permission column holds it.
#[cfg(feature = "prover")]
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Permission {
    Unmapped = 0,
    Readable = 1,
    Writable = 2,
}

#[cfg(feature = "prover")]
impl MemoryLayout {
    /// Every page writable: a machine with no layout, as a flat test
    /// memory is. A kernel's proof never takes it: its identity would let
    /// every page fault prove.
    pub const fn writable() -> Self {
        let none = PageRange { first: 0, end: 0 };
        Self {
            regions: [
                none,
                none,
                PageRange {
                    first: 0,
                    end: 1 << crate::page_merkle::DEPTH,
                },
                none,
            ],
        }
    }

    /// A standard program's layout, as `derive` lays a kernel out: its
    /// read-only data and argument window readable, its read-write data
    /// with its heap and its stack writable.
    pub fn standard(layout: &vos_pvm::spi::StandardLayout<'_>) -> Self {
        let page = u64::from(vos_pvm::PVM_PAGE_SIZE);
        let pages = |region: vos_pvm::spi::SpiRegion| PageRange {
            first: (region.base / page) as u32,
            end: ((region.base + region.size) / page) as u32,
        };
        Self {
            regions: [
                pages(layout.ro),
                pages(layout.args),
                pages(layout.rw),
                pages(layout.stack),
            ],
        }
    }

    /// Whether no page lies in two regions: a page selects the region it
    /// lies in, so overlapping regions would let it pick the permissive
    /// one.
    pub fn is_disjoint(&self) -> bool {
        self.regions.iter().enumerate().all(|(k, a)| {
            self.regions[k + 1..]
                .iter()
                .all(|b| a.first.max(b.first) >= a.end.min(b.end))
        })
    }

    /// The region `page` lies in, if any.
    pub fn region_of(&self, page: u32) -> Option<usize> {
        self.regions
            .iter()
            .position(|range| range.first <= page && page < range.end)
    }

    /// What `page` allows.
    pub fn permission(&self, page: u32) -> Permission {
        match self.region_of(page) {
            None => Permission::Unmapped,
            Some(region) if region < FIRST_WRITABLE => Permission::Readable,
            Some(_) => Permission::Writable,
        }
    }
}
