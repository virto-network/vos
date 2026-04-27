#![cfg_attr(not(feature = "prover"), no_std)]

extern crate alloc;

pub mod air_column;
pub mod core;
pub mod trace;
pub mod chips;
mod framework;
mod lookups;
pub mod framework_access;
pub mod proof;

#[cfg(feature = "prover")]
pub mod side_note;

#[cfg(feature = "prover")]
mod prove;
#[cfg(feature = "prover")]
mod verify;

// Re-export AirColumn + PreprocessedAirColumn at crate root so the derive-
// generated impls (which target `::zkpvm::AirColumn`) resolve correctly.
pub use air_column::{AirColumn, PreprocessedAirColumn};

// Ordering rule: all consumers of a lookup table must be listed BEFORE the table
// chip itself.  Table chips populate their multiplicity column by reading counts
// that consumers accumulate into SideNote during trace generation.
#[cfg(feature = "prover")]
const BASE_COMPONENTS: &[&dyn framework::MachineProverComponent] = &[
    &chips::CpuChip,
    &chips::Blake2bChip, // consumes Bitwise AND lookup
    &chips::MemoryChip,
    &chips::MemoryBoundaryChip,
    &chips::RegisterMemoryChip,
    &chips::RegisterMemoryBoundaryChip,
    &chips::ProgramBoundaryChip,
    &chips::ProgramMemoryChip, // 13a — producer-only until CpuChip consumer in 13b
    &chips::RangeMultiplicity256,
    &chips::BitwiseLookupChip,
    &chips::PowerOfTwoChip,
];

#[cfg(not(feature = "prover"))]
const BASE_COMPONENTS: &[&dyn framework::MachineComponent] = &[
    &chips::CpuChip,
    &chips::Blake2bChip,
    &chips::MemoryChip,
    &chips::MemoryBoundaryChip,
    &chips::RegisterMemoryChip,
    &chips::RegisterMemoryBoundaryChip,
    &chips::ProgramBoundaryChip,
    &chips::ProgramMemoryChip,
    &chips::RangeMultiplicity256,
    &chips::BitwiseLookupChip,
    &chips::PowerOfTwoChip,
];

pub use proof::{Proof, SegmentState};
#[cfg(feature = "prover")]
pub use prove::{prove, prove_with_config, prove_profiled, prove_profiled_with_config, ProveProfile, production_pcs_config};
#[cfg(feature = "prover")]
pub use prove::debug_claimed_sums;
pub use stwo::core::pcs::PcsConfig;
pub use stwo::core::fri::FriConfig;
#[cfg(feature = "prover")]
pub use verify::{verify, verify_chain};
#[cfg(feature = "prover")]
pub use side_note::SideNote;
