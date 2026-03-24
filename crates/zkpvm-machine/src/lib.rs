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
    &chips::ProgramBoundaryChip,
    &chips::BitwiseLookupChip,
];

pub use prove::{prove, Proof};
pub use verify::verify;
pub use side_note::SideNote;
