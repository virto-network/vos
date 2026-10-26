//! The device profile's shape (`docs/design/slice-7-mobile.md`, pin J): a
//! kernel's whole run as one segment, without the page-Merkle boundary.
//!
//! - **The chips** are the shared chip set's (format 35's chips, the
//!   Poseidon2 chip, and the CPU that acknowledges its call,
//!   [`chips::CpuP2Chip`](crate::chips::CpuP2Chip)) without the page
//!   boundary (BLAKE2B_BOUNDARY, MEMORY_PAGE, MEMORY_MERKLE,
//!   MEMORY_ROOT_BOUNDARY) or the node's boundary chips (the registers in and
//!   out, the program's boundary), and with the device's own:
//!   [`DeviceMemoryChip`](crate::chips::DeviceMemoryChip) (first touches and
//!   closing reads), [`DataTableChip`](crate::chips::DataTableChip) (the
//!   program's data), [`DeviceBoundaryChip`](crate::chips::DeviceBoundaryChip)
//!   (the run's entry and halt) and [`DeviceIoChip`](crate::chips::DeviceIoChip)
//!   (the io-hash, the only public output). Their indices continue
//!   [`chip_idx`]'s ([`device_chip`]); [`DEVICE_ORDER`] is
//!   the set's commitment order.
//! - **The run is bound** by the program's code (PROGRAM_MEMORY,
//!   preprocessed); its first touches by region ([`DeviceLayout`]): the
//!   read-only data and the read-write data as a preprocessed data table, the
//!   argument window, the heap and the stack zero, any other address none;
//!   each region's permission preprocessed, so no write lands on a readable
//!   page; its entry (timestamp 1, pc 0, the layout's registers) and its halt
//!   (pc [`HALT_PC`]) as constants; its output through the io-hash in
//!   φ9..12 alone.
//! - **The shape is the program's**, never the run's: the chips its code can
//!   reach ([`device_chips_of_code`]) and a log size each, which the prover
//!   pads to and refuses a run beyond.

use crate::chip_idx;

/// The shared chip set's indices: [`chip_idx`]'s, then the device's. The
/// CPU at [`chip_idx::CPU`] is the shared set's
/// ([`CpuP2Chip`](crate::chips::CpuP2Chip)) in a device shape.
pub mod device_chip {
    pub use crate::chip_idx::*;

    /// One Poseidon2-M31 permutation a call (pin H).
    pub const POSEIDON2: usize = super::chip_idx::COUNT;
    /// The run's first touches and closing reads, a row a byte it touches.
    pub const DEVICE_MEMORY: usize = POSEIDON2 + 1;
    /// The program's data bytes, preprocessed.
    pub const DATA_TABLE: usize = POSEIDON2 + 2;
    /// The run's entry and halt: the registers in and out.
    pub const DEVICE_BOUNDARY: usize = POSEIDON2 + 3;
    /// The io-hash, φ9..12 at the halt: the public output.
    pub const DEVICE_IO: usize = POSEIDON2 + 4;
    /// The shared index space's size.
    pub const SHARED_COUNT: usize = POSEIDON2 + 5;
}

const _: () = assert!(device_chip::SHARED_COUNT <= 32);

/// A device shape's chips in commitment and generation order: every
/// consumer of a table before it, the producers (the CPU, BLAKE2b, the
/// Poseidon2 chip, the witness input) before the range table.
pub const DEVICE_ORDER: [usize; 23] = {
    use device_chip::*;
    [
        CPU,
        BLAKE2B,
        POSEIDON2,
        MEMORY,
        DEVICE_MEMORY,
        DATA_TABLE,
        REGISTER_MEMORY,
        DEVICE_BOUNDARY,
        DEVICE_IO,
        PROGRAM_MEMORY,
        JUMP_TABLE,
        WITNESS_INPUT,
        RANGE_MULTIPLICITY_256,
        BITWISE_LOOKUP,
        POWER_OF_TWO,
        POPCOUNT,
        BITCOUNT,
        BYTE_TO_BITS,
        MUL,
        BITWISE,
        COMPARE,
        DIVREM,
        BITWISE_AND_BYTE,
    ]
};

/// The chips every device shape holds.
pub const DEVICE_ALWAYS: u32 = {
    use device_chip::*;
    1 << CPU
        | 1 << MEMORY
        | 1 << DEVICE_MEMORY
        | 1 << DATA_TABLE
        | 1 << REGISTER_MEMORY
        | 1 << DEVICE_BOUNDARY
        | 1 << DEVICE_IO
        | 1 << PROGRAM_MEMORY
        | 1 << RANGE_MULTIPLICITY_256
        | 1 << BITWISE_LOOKUP
        | 1 << POWER_OF_TWO
        | 1 << BYTE_TO_BITS
};

/// The chips a device shape holds when its code reaches them: format 35's
/// optional chips, the byte-wide AND table with BLAKE2b (its only consumer
/// once the page boundary is gone), and the Poseidon2 chip.
pub const DEVICE_OPTIONAL: u32 =
    chip_idx::OPTIONAL | 1 << chip_idx::BITWISE_AND_BYTE | 1 << device_chip::POSEIDON2;

/// Every chip a device shape may hold.
pub const DEVICE_ALL: u32 = DEVICE_ALWAYS | DEVICE_OPTIONAL;

const _: () = {
    let mut mask = 0u32;
    let mut i = 0;
    while i < DEVICE_ORDER.len() {
        mask |= 1 << DEVICE_ORDER[i];
        i += 1;
    }
    assert!(mask == DEVICE_ALL);
};

/// The chips a device mask names, in [`DEVICE_ORDER`].
pub fn device_chips_of_mask(active: u32) -> impl Iterator<Item = usize> {
    DEVICE_ORDER
        .into_iter()
        .filter(move |&chip| active & 1 << chip != 0)
}

/// Whether `active` is a device shape's chips: every chip it always holds,
/// none outside the set.
pub const fn is_device_mask(active: u32) -> bool {
    active & DEVICE_ALWAYS == DEVICE_ALWAYS && active & !DEVICE_ALL == 0
}

/// The pc a halted run ends at: φ0's at entry, the standard layout's halt
/// address, the low four bytes of `vos_pvm_program::HALT_ADDRESS`.
pub const HALT_PC: u32 = vos_pvm_program::HALT_ADDRESS as u32;

/// The pc and the timestamp a run's first step takes.
pub const ENTRY_PC: u32 = 0;
pub const ENTRY_TIMESTAMP: u64 = 1;

/// A device layout's regions, by index: the read-only data, the argument
/// window, the read-write data, the heap and the stack.
pub mod region {
    pub const RO: usize = 0;
    pub const ARGS: usize = 1;
    pub const RW_DATA: usize = 2;
    pub const HEAP: usize = 3;
    pub const STACK: usize = 4;
    /// The regions.
    pub const COUNT: usize = 5;
    /// Whether a region is readable only (else writable).
    pub const READABLE_ONLY: [bool; COUNT] = [true, true, false, false, false];
    /// Whether a region's first touches are the data table's (else zero).
    pub const DATA: [bool; COUNT] = [true, false, true, false, false];
}

/// The pages a device program may touch and what each first touch reads:
/// [`region::COUNT`] regions of whole pages, each readable only or writable,
/// each its data table's bytes or zero; every other page none.
#[cfg(feature = "prover")]
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

#[cfg(feature = "prover")]
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

    /// The byte a first touch of `address` reads: its data table's in a
    /// data region, zero elsewhere.
    pub fn initial_byte(&self, address: u32) -> u8 {
        self.data
            .iter()
            .find_map(|(base, bytes)| {
                address
                    .checked_sub(*base)
                    .and_then(|offset| bytes.get(offset as usize))
                    .copied()
            })
            .unwrap_or(0)
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

/// A byte a device run touches: its address, the byte its first touch
/// reads, and the byte it holds at the halt.
#[cfg(feature = "prover")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Touched {
    pub address: u32,
    pub initial: u8,
    pub last: u8,
}

/// A device run's boundary: its layout and the bytes it touches, in
/// address order; what `MemoryChip`, [`DeviceMemoryChip`] and
/// [`DataTableChip`] take in place of the page boundary.
///
/// [`DeviceMemoryChip`]: crate::chips::DeviceMemoryChip
/// [`DataTableChip`]: crate::chips::DataTableChip
#[cfg(feature = "prover")]
#[derive(Clone, Debug)]
pub struct DeviceRun {
    pub layout: DeviceLayout,
    pub touched: alloc::vec::Vec<Touched>,
}

#[cfg(feature = "prover")]
impl DeviceRun {
    /// `side_note`'s run under `layout`: every byte its ledger accesses,
    /// with the byte its entering image holds there (what its first touch
    /// reads) and its last value. A run whose entering image is not the
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
        let mut touched: alloc::vec::Vec<Touched> = alloc::vec::Vec::new();
        for entry in &entries {
            match touched.last_mut() {
                Some(last) if last.address == entry.address => {
                    last.last = entry.value;
                }
                _ => {
                    let initial = entering(entry.address);
                    touched.push(Touched {
                        address: entry.address,
                        initial,
                        last: if entry.is_write { entry.value } else { initial },
                    });
                }
            }
        }
        Self { layout, touched }
    }

    /// No run: the layout alone, what a program's preprocessed columns are
    /// computed from.
    pub fn empty(layout: DeviceLayout) -> Self {
        Self {
            layout,
            touched: alloc::vec::Vec::new(),
        }
    }
}

/// The chips a device shape of `code` holds, its instruction starts marked
/// in `bitmask`: every chip it always holds, each instruction's opcode's,
/// and each precompile's an `ecalli` names. From the code alone, so a path a
/// run does not take is covered and the shape is the program's.
#[cfg(feature = "prover")]
pub fn device_chips_of_code(code: &[u8], bitmask: &[u8]) -> u32 {
    use crate::core::ecall::{ECALL_BLAKE2B_COMPRESS, ECALL_POSEIDON2, ECALL_WITNESS_INPUT};
    use vos_pvm::instruction::{Opcode, decode_opcode_fast};
    let mut chips = DEVICE_ALWAYS;
    for (pc, &byte) in code.iter().enumerate() {
        if bitmask.get(pc) != Some(&1) {
            continue;
        }
        let Some((op, category)) = decode_opcode_fast(byte) else {
            continue;
        };
        chips |= crate::opcode_component_mask(op) & chip_idx::OPTIONAL;
        if op == Opcode::Ecalli {
            let skip = vos_pvm::gas_cost::skip_distance(bitmask, pc);
            if let vos_pvm::args::Args::Imm { imm } =
                vos_pvm::args::decode_args(code, pc, skip, category)
            {
                chips |= match imm {
                    id if id == u64::from(ECALL_BLAKE2B_COMPRESS) => {
                        1 << chip_idx::BLAKE2B | 1 << chip_idx::BITWISE_AND_BYTE
                    }
                    id if id == u64::from(ECALL_WITNESS_INPUT) => {
                        1 << chip_idx::WITNESS_INPUT | 1 << chip_idx::COMPARE
                    }
                    id if id == u64::from(ECALL_POSEIDON2) => 1 << device_chip::POSEIDON2,
                    _ => 0,
                };
            }
        }
    }
    chips
}
