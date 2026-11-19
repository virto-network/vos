//! The pages a program may touch, and how: four regions of whole pages,
//! the first [`FIRST_WRITABLE`] readable, the rest writable, which
//! MemoryPageChip's preprocessed region columns hold, so part of the
//! program's identity.

/// A layout's regions: the first [`FIRST_WRITABLE`] readable, the rest
/// writable.
pub const REGIONS: usize = 4;
pub const FIRST_WRITABLE: usize = 2;

/// The pages `[first, end)`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PageRange {
    pub first: u32,
    pub end: u32,
}

#[cfg(feature = "prover")]
mod host;
#[cfg(feature = "prover")]
pub use host::{MemoryLayout, Permission};
