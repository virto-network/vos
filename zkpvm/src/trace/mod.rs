#[cfg(feature = "prover")]
pub mod builder;
#[cfg(feature = "prover")]
pub mod component;
pub mod eval;
#[cfg(feature = "prover")]
pub mod utils;
#[cfg(feature = "prover")]
pub mod virtual_column;

#[cfg(feature = "prover")]
mod utils_external;

// Re-export the `#[macro_export]` macros here so call sites can address them
// via `crate::trace::trace_eval!` instead of the crate-root path (the real
// path #[macro_export] puts them at).  Verifier-facing macros stay always-
// compiled; the prover-only ones (defined alongside ComponentTrace) follow
// the gate.
#[cfg(feature = "prover")]
pub use crate::{original_base_column, preprocessed_base_column};
pub use crate::{preprocessed_trace_eval, trace_eval, trace_eval_next_row};
