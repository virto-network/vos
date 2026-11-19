//! A device program's layout: its regions and its data, from its blob.

use super::*;

/// The pages a device program may touch and what each first touch reads:
/// [`region::COUNT`] regions of whole pages, each readable only or writable,
/// each its data table's bytes or zero; every other page none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceLayout {
    /// Each region's pages, `[first, end)`.
    pub regions: [crate::memory_layout::PageRange; region::COUNT],
    /// The data table: each data region's bytes from its first page, zero
    /// to its end.
    pub data: alloc::vec::Vec<(u32, alloc::vec::Vec<u8>)>,
    /// The registers at entry, the layout's.
    pub registers: [u64; crate::core::step::NUM_REGS],
}

impl DeviceLayout {
    /// Standard program `blob`'s, laid out with no arguments as a kernel is:
    /// its read-only data and its read-write data a data table each, the
    /// heap after the read-write data's pages, the stack, the (empty)
    /// argument window. `None` for a blob that is not a standard program.
    pub fn of_program(blob: &[u8]) -> Option<Self> {
        use crate::memory_layout::PageRange;
        let page = vos_pvm_program::PAGE_SIZE;
        let program = vos_pvm_program::parse_standard_program(blob)?;
        let layout = program.layout(&[])?;
        let pages = |base: u64, size: u64| PageRange {
            first: (base / u64::from(page)) as u32,
            end: ((base + size) / u64::from(page)) as u32,
        };
        let rw = pages(layout.rw.base, layout.rw.size);
        let rw_data_end = rw.first + (layout.rw_data.len() as u32).div_ceil(page);
        let padded = |bytes: &[u8]| {
            let mut bytes = bytes.to_vec();
            bytes.resize(bytes.len().div_ceil(page as usize) * page as usize, 0);
            bytes
        };
        let ro = pages(layout.ro.base, layout.ro.size);
        Some(Self {
            regions: [
                ro,
                pages(layout.args.base, layout.args.size),
                PageRange {
                    first: rw.first,
                    end: rw_data_end,
                },
                PageRange {
                    first: rw_data_end,
                    end: rw.end,
                },
                pages(layout.stack.base, layout.stack.size),
            ],
            data: alloc::vec![
                (ro.first * page, padded(layout.ro_data)),
                (rw.first * page, padded(layout.rw_data)),
            ],
            registers: layout.registers,
        })
    }

    /// The region `address` lies in, if any.
    pub fn region_of(&self, address: u32) -> Option<usize> {
        let page = address / vos_pvm_program::PAGE_SIZE;
        self.regions
            .iter()
            .position(|range| range.first <= page && page < range.end)
    }

    /// Whether no page lies in two regions.
    pub fn is_disjoint(&self) -> bool {
        self.regions.iter().enumerate().all(|(k, a)| {
            self.regions[k + 1..]
                .iter()
                .all(|b| a.first.max(b.first) >= a.end.min(b.end))
        })
    }
}
