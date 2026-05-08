//! Init argument types for actor constructors.
//!
//! Re-exports `Value` and `Args` under init-specific aliases for
//! backward compatibility and clarity in init-specific contexts.

pub use super::value::{Args as InitArgs, Value as InitValue};
