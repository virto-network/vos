//! The Polkadot Virtual Machine of Gray Paper v0.8.0 (Appendix A).
//!
//! The PVM is a register-based virtual machine with:
//! - 13 general-purpose 64-bit registers (φ₀..φ₁₂)
//! - 32-bit pageable memory address space
//! - Gas metering for bounded execution
//! - Host-call interface for system interactions

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;

pub mod accumulate_host;
pub mod args;
pub mod backend;
#[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
pub mod backing;
pub mod gas_cost;
pub mod gas_sim;
pub mod inner;
pub mod instruction;
pub mod interpreter;
#[cfg(feature = "std")]
pub mod pool;
pub mod precompile;
pub mod refine;
pub mod refine_host;
pub mod spi;
// Real JIT recompiler on Linux x86-64.
#[cfg(all(feature = "std", target_os = "linux", target_arch = "x86_64"))]
pub mod recompiler;

pub use backend::PvmBackend;
pub use interpreter::Interpreter;

/// Standard PVM specification version implemented by the portable path.
pub const STANDARD_PVM_SPEC_VERSION: &str = "0.8.0";

/// Exact upstream specification commit used for the standard PVM contract.
pub const STANDARD_PVM_SPEC_REVISION: &str = "07f041dabd073f9018b418e9ee72e79dd2185401";

// --- PVM types ---

/// Exit reason for PVM execution (ε values, eq A.1).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExitReason {
    /// ∎: Normal halt.
    Halt,
    /// ☇: Panic / runtime error (trap, bad djump, invalid opcode).
    Panic,
    /// ∞: Out of gas.
    OutOfGas,
    /// ×: Page fault at the given page address.
    PageFault(u32),
    /// h̵: Host-call with the given identifier (ecalli).
    HostCall(u64),
}

// --- PVM constants (Gray Paper Appendix A / I.4.4) ---

/// Gas type: NG = N_{2^64} (eq 4.23).
pub type Gas = u64;

/// A host call that has been surfaced but not yet acknowledged by the host.
///
/// Standard execution keeps the architectural instruction counter at
/// `cause_pc` until the host explicitly commits the call.  `resume_pc` is the
/// sequential successor selected by the decoded `ecalli`; keeping both values
/// is necessary for deterministic retry and portable continuations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PendingHostCall {
    pub id: u64,
    pub cause_pc: u32,
    pub resume_pc: u32,
}

/// ZP = 2^12 = 4096: PVM memory page size.
pub const PVM_PAGE_SIZE: u32 = 1 << 12;

/// The dynamic-jump halt address: 2^32 − 2^16 (GP eq A.18).
///
/// A djump to this address is a normal halt (∎). Standard program
/// initialization sets ω\[0\] (RA) to it, so `ret` from the entry point
/// halts the VM.
pub const PVM_HALT_ADDR: u64 = (1 << 32) - (1 << 16);

/// ZI = 2^24: Standard PVM program initialization input data size.
pub const PVM_INIT_INPUT_SIZE: u32 = 1 << 24;

/// ZZ = 2^16 = 65536: Standard PVM program initialization zone size.
pub const PVM_ZONE_SIZE: u32 = 1 << 16;

/// Number of registers in the PVM.
pub const PVM_REGISTER_COUNT: usize = 13;

/// Fixed load/store latency from Gray Paper v0.8.0 equation A.58.
pub const STANDARD_MEM_CYCLES: u8 = 25;
