pub mod builder;
pub mod component;
pub mod eval;
pub mod utils;
pub mod virtual_column;

mod utils_external;

// Re-export the `#[macro_export]` macros here so call sites can address them
// via `crate::trace::trace_eval!` instead of the crate-root path (the real
// path #[macro_export] puts them at).
pub use crate::{
    original_base_column, preprocessed_base_column, preprocessed_trace_eval, trace_eval,
    trace_eval_next_row,
};
