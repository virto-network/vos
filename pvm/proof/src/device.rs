//! The device profile's shape (`docs/design/proving.md` §8): a
//! kernel's whole run as one segment, without the page-Merkle boundary.
//!
//! - **The chips** are the shared chip set's, the segment AIR's
//!   ([`chip_idx`]: the CPU, the Poseidon2 chip among them), without the
//!   page boundary (BLAKE2B_BOUNDARY, MEMORY_PAGE, MEMORY_MERKLE,
//!   MEMORY_ROOT_BOUNDARY) or the node's boundary chips (the registers in and
//!   out, the program's boundary), and with the device's own:
//!   the word ledger ([`WordMemoryChip`](crate::chips::WordMemoryChip) in
//!   the memory chip's place, a row a word an access touches),
//!   [`DeviceWordMemoryChip`](crate::chips::DeviceWordMemoryChip) (first
//!   touches and closing reads, a row a word),
//!   [`DataWordTableChip`](crate::chips::DataWordTableChip) (the program's
//!   data), [`DeviceBoundaryChip`](crate::chips::DeviceBoundaryChip)
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
//!   (pc [`HALT_PC`](crate::program_id::HALT_PC)) as constants; its output through the io-hash in
//!   φ9..12 alone.
//! - **The shape is the program's**, never the run's: the chips its code can
//!   reach ([`device_chips_of_code`]) and a log size each, which the prover
//!   pads to and refuses a run beyond.

use crate::chip_idx;

/// The shared chip set's indices: [`chip_idx`]'s, then the device's.
pub mod device_chip {
    pub use crate::chip_idx::*;

    /// The run's first touches and closing reads, a row a word it touches.
    pub const DEVICE_MEMORY: usize = COUNT;
    /// The program's data words, preprocessed.
    pub const DATA_TABLE: usize = COUNT + 1;
    /// The run's entry and halt: the registers in and out.
    pub const DEVICE_BOUNDARY: usize = COUNT + 2;
    /// The io-hash, φ9..12 at the halt: the public output.
    pub const DEVICE_IO: usize = COUNT + 3;
    /// The shared index space's size.
    pub const SHARED_COUNT: usize = COUNT + 4;
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

/// The chips a device shape may hold beside those it always does: the
/// segment AIR's optional chips (the Poseidon2 chip among them), and the
/// byte-wide AND table with BLAKE2b (its only consumer once the page
/// boundary is gone). The chip set is the AIR's; a device program holds
/// those its code reaches, and BLAKE2b's never: [`device_chips_of_code`]
/// refuses a code naming its precompile.
pub const DEVICE_OPTIONAL: u32 = chip_idx::OPTIONAL | 1 << chip_idx::BITWISE_AND_BYTE;

/// Every chip a device shape may hold.
pub const DEVICE_ALL: u32 = DEVICE_ALWAYS | DEVICE_OPTIONAL;

/// The most rows a device program's chip takes, `2^17`: the memory ledger,
/// rows by the bytes a run touches, outgrows the steps (the auth
/// statements' ledgers take 2^17 rows at about 19,000 steps). The device format's security
/// count is taken with every chip at it (`format::DEVICE_REFERENCE`), so a
/// program with a taller chip is refused at install.
pub const DEVICE_MAX_LOG_SIZE: u32 = 17;

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

/// A device program's components: its chips, a device mask; and its CPU's
/// columns, the program's ([`crate::chips::CpuColumns::of_code`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DeviceShape {
    pub chips: u32,
    pub cpu: crate::chips::CpuColumns,
}

impl From<u32> for DeviceShape {
    /// The chips `chips`, the CPU every column.
    fn from(chips: u32) -> Self {
        Self {
            chips,
            cpu: crate::chips::CpuColumns::ALL,
        }
    }
}

impl DeviceShape {
    /// The per-program CPU the shape holds, `None` for the full CPU.
    pub fn program_cpu(&self) -> Option<crate::chips::ProgramCpuChip> {
        (self.cpu != crate::chips::CpuColumns::ALL)
            .then(|| crate::chips::ProgramCpuChip::new(self.cpu))
    }
}

/// The pc a run's first step takes; its timestamp and its halt pc are a
/// kernel's (`program_id::{ENTRY_TIMESTAMP, HALT_PC}`).
pub const ENTRY_PC: u32 = 0;

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

/// The bytes of a word of the word ledger.
pub const WORD_BYTES: usize = crate::lookups::MEMORY_WORD_SIZE;

#[cfg(feature = "prover")]
mod pin;
#[cfg(feature = "prover")]
mod run;
#[cfg(feature = "prover")]
pub use pin::device_chips_of_code;
#[cfg(feature = "prover")]
pub use run::{DeviceLayout, DeviceRun, TouchedWord};
