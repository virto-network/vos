//! PVM guest-side support for VOS actors compiled to RISC-V.
//!
//! Provides:
//! - Raw ecall interface
//! - Bump allocator
//! - Typed hostcall wrappers

mod alloc;

pub mod ecall;
pub mod hostcalls;
