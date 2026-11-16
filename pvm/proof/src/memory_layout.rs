//! The pages a program may touch, and how: four regions of whole pages,
//! the first [`FIRST_WRITABLE`] readable, the rest writable, which
//! MemoryPageChip's preprocessed region columns hold, so part of the
//! program's identity.

/// A layout's regions: the first [`FIRST_WRITABLE`] readable, the rest
/// writable.
pub const REGIONS: usize = 4;
pub const FIRST_WRITABLE: usize = 2;

#[cfg(feature = "prover")]
mod host;
#[cfg(feature = "prover")]
pub use host::{MemoryLayout, PageRange, Permission};
