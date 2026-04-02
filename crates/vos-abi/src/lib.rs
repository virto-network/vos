//! # vos-abi
//!
//! JAR-aligned ABI for VOS actors. Zero dependencies, `no_std`.
//!
//! Defines:
//! - **Hostcall IDs**: phase-split modules (`hostcall::refine`, `hostcall::accumulate`)
//! - **Error codes**: JAR result codes (HOST_OK, HOST_NONE, etc.)
//! - **ServiceId**: service identity type
//! - **PVM module** (feature-gated): ecall assembly, bump allocator, typed hostcall wrappers

#![no_std]

pub mod error;
pub mod hostcall;
pub mod service;

/// PVM guest-side support: ecall interface, allocator, typed hostcall wrappers.
#[cfg(feature = "pvm")]
pub mod pvm;
