mod chips;
mod framework;
mod lookups;
pub mod framework_access;
pub mod side_note;

mod prove;
mod verify;

const BASE_COMPONENTS: &[&dyn framework::MachineComponent] = &[
    &chips::CpuChip,
    &chips::RangeMultiplicity256,
    &chips::MemoryChip,
    &chips::MemoryBoundaryChip,
    &chips::ProgramBoundaryChip,
    &chips::BitwiseLookupChip,
    &chips::PowerOfTwoChip,
];

pub use prove::{prove, prove_with_config, prove_profiled, prove_profiled_with_config, Proof, ProveProfile, production_pcs_config};
pub use prove::debug_claimed_sums;
pub use stwo::core::pcs::PcsConfig;
pub use stwo::core::fri::FriConfig;
pub use verify::verify;
pub use side_note::SideNote;
