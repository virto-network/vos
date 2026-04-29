//! PVM guest-side support for VOS actors compiled to RISC-V.
//!
//! Provides:
//! - Raw ecall interface
//! - Bump allocator
//! - Typed hostcall wrappers

// Guest-only #[global_allocator]. Same gating as `guest_panic`:
// only when we're a no_std guest, never alongside std (which
// brings its own allocator).
#[cfg(not(feature = "std"))]
mod alloc;

pub mod ecall;
pub mod hostcalls;
