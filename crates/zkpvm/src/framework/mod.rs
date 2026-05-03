pub(crate) mod eval;
mod traits;

pub(crate) use traits::builtin::BuiltInComponent;
pub(crate) use traits::erased::MachineComponent;

#[cfg(feature = "prover")]
pub(crate) use traits::{
    builtin::BuiltInProverComponent,
    erased::MachineProverComponent,
};
