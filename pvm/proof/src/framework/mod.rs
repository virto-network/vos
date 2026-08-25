pub(crate) mod eval;
mod traits;

pub(crate) use traits::builtin::BuiltInComponent;
// `MachineComponent` is re-exported through `crate::harness` for the
// chip-isolated prove API.
pub use traits::erased::MachineComponent;

#[cfg(feature = "prover")]
pub(crate) use traits::builtin::BuiltInProverComponent;
#[cfg(feature = "prover")]
pub use traits::erased::MachineProverComponent;
