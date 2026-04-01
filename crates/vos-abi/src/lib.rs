//! # vos-abi
//!
//! JAR-aligned ABI for VOS actors. Zero dependencies, `no_std`.
//!
//! Defines:
//! - **Hostcall IDs**: phase-split modules (`hostcall::refine`, `hostcall::accumulate`)
//!   with deprecated flat aliases for transition
//! - **Error codes**: JAR result codes (HOST_OK, HOST_NONE, etc.)
//! - **ServiceId**: service identity type
//! - **TransferMemo**: 128-byte transfer metadata
//! - **Guest module** (feature-gated): ecall assembly, bump allocator, typed hostcall wrappers

#![no_std]

pub mod error;
pub mod hostcall;
pub mod msg;
pub mod service;

#[cfg(feature = "guest")]
pub mod guest;
