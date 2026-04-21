pub mod chips;
mod framework;
mod lookups;
pub mod framework_access;
pub mod side_note;

mod prove;
mod verify;

// Ordering rule: all consumers of a lookup table must be listed BEFORE the table
// chip itself.  Table chips populate their multiplicity column by reading counts
// that consumers accumulate into SideNote during trace generation.
const BASE_COMPONENTS: &[&dyn framework::MachineComponent] = &[
    &chips::CpuChip,
    &chips::Blake2bChip, // consumes Bitwise AND lookup
    &chips::MemoryChip,
    &chips::MemoryBoundaryChip,
    &chips::ProgramBoundaryChip,
    &chips::RangeMultiplicity256,
    &chips::BitwiseLookupChip,
    &chips::PowerOfTwoChip,
];

pub use prove::{prove, prove_with_config, prove_profiled, prove_profiled_with_config, Proof, ProveProfile, SegmentState, production_pcs_config};
pub use prove::debug_claimed_sums;
pub use stwo::core::pcs::PcsConfig;
pub use stwo::core::fri::FriConfig;
pub use verify::{verify, verify_chain};
pub use side_note::SideNote;
