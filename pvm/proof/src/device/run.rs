//! A device run's touched words, the prover's half.

use super::*;

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
