//! JAR-aligned ABI for VOS actors.
//!
//! Defines:
//! - **Hostcall IDs**: protocol capability slot numbers
//! - **Error codes**: JAR result codes (HOST_OK, HOST_NONE, etc.)
//! - **ServiceId**: service identity type
//! - **PVM module** (feature-gated): ecall assembly, bump allocator, typed hostcall wrappers

pub mod error;
pub mod hostcall;
pub mod service;

/// PVM guest-side support: ecall interface, allocator, typed hostcall wrappers.
#[cfg(feature = "pvm")]
pub mod pvm;
