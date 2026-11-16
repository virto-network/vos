//! A device run's layout and touched words, the prover's half.

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

    /// The data table's entries, address and byte.
    pub fn data_entries(&self) -> impl Iterator<Item = (u32, u8)> + '_ {
        self.data.iter().flat_map(|(base, bytes)| {
            bytes
                .iter()
                .enumerate()
                .map(move |(offset, &byte)| (base + offset as u32, byte))
        })
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

/// A word a device run touches a byte of: its address, a multiple of
/// [`WORD_BYTES`], the bytes its first touch reads and those it holds at the
/// halt, every byte of the word's, touched or not.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TouchedWord {
    pub address: u32,
    pub initial: [u8; WORD_BYTES],
    pub last: [u8; WORD_BYTES],
}

/// A device run's boundary: its layout and the words it touches a byte of,
/// in address order; what the word ledger, its boundary
/// chip ([`DeviceWordMemoryChip`]) and the data table take in place of the
/// page boundary.
///
/// [`DeviceWordMemoryChip`]: crate::chips::DeviceWordMemoryChip
#[derive(Clone, Debug)]
pub struct DeviceRun {
    pub layout: DeviceLayout,
    pub words: alloc::vec::Vec<TouchedWord>,
}

impl DeviceRun {
    /// `side_note`'s run under `layout`: every word its ledger accesses a
    /// byte of, with the bytes its entering image holds there (what its
    /// first touch reads) and its last value. A run whose entering image is not the
    /// layout's where it touches (a data byte not the table's, a stack or
    /// heap byte not zero) is not the program's from its entry: its proof is
    /// refused.
    pub fn of(side_note: &crate::side_note::SideNote, layout: DeviceLayout) -> Self {
        let entering = |address: u32| match &side_note.sparse_initial_memory {
            Some(image) => image.byte(address),
            None => side_note
                .initial_memory
                .get(address as usize)
                .copied()
                .unwrap_or(0),
        };
        let mut entries = crate::chips::memory::access_entries(side_note);
        entries.sort_by_key(|entry| (entry.address, entry.timestamp, entry.is_write));
        // Each byte the ledger accesses, its address and its last value.
        let mut touched: alloc::vec::Vec<(u32, u8)> = alloc::vec::Vec::new();
        for entry in &entries {
            match touched.last_mut() {
                Some((address, last)) if *address == entry.address => *last = entry.value,
                _ => touched.push((
                    entry.address,
                    if entry.is_write {
                        entry.value
                    } else {
                        entering(entry.address)
                    },
                )),
            }
        }
        let mut words: alloc::vec::Vec<TouchedWord> = alloc::vec::Vec::new();
        for (byte, last) in touched {
            let address = byte & !(WORD_BYTES as u32 - 1);
            if words.last().is_none_or(|word| word.address != address) {
                let initial =
                    core::array::from_fn(|lane| entering(address.wrapping_add(lane as u32)));
                words.push(TouchedWord {
                    address,
                    initial,
                    last: initial,
                });
            }
            let word = words.last_mut().expect("the byte's word");
            word.last[(byte - address) as usize] = last;
        }
        Self { layout, words }
    }

    /// No run: the layout alone, what a program's preprocessed columns are
    /// computed from.
    pub fn empty(layout: DeviceLayout) -> Self {
        Self {
            layout,
            words: alloc::vec::Vec::new(),
        }
    }
}
