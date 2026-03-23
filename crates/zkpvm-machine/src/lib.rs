mod chips;
mod framework;
mod lookups;
pub mod side_note;

mod prove;
mod verify;

const BASE_COMPONENTS: &[&dyn framework::MachineComponent] = &[
    &chips::CpuChip,
    &chips::RangeMultiplicity256,
    &chips::MemoryChip,
];

pub use prove::{prove, Proof};
pub use verify::verify;
pub use side_note::SideNote;
