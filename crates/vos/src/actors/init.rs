//! Init argument types for actor constructors.
//!
//! Re-exports `Value` and `Args` under init-specific aliases for
//! backward compatibility and clarity in init-specific contexts.

pub use super::value::{Value as InitValue, Args as InitArgs};
