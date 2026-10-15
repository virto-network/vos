//! The default agent program.
//!
//! Refine (instruction 0) runs a batch of inputs as steps, each an actor
//! invocation in an inner machine, and returns the work result; or runs a
//! query and returns its outcome. Accumulate (instruction 5) applies work
//! results to the agent's storage with the Gray Paper's `write`.

#![no_std]
#![no_main]

extern crate alloc;

mod accumulate;
mod refine;

use vos_agent::{host, machines};
use vos_sdk::runtime::Output;

// The heap holds a batch's overlays and its output, up to
// `vos_wire::abi::cap::OUTPUT`.
vos_sdk::program_runtime!(64 << 20);

core::arch::global_asm!(
    ".global _start",
    ".type _start, @function",
    "_start:",
    "mv s0, ra",
    "jal ra, vos_refine",
    "mv ra, s0",
    "ret",
    ".global accumulate",
    ".type accumulate, @function",
    "accumulate:",
    "mv s0, ra",
    "jal ra, vos_accumulate",
    "mv ra, s0",
    "ret",
);

/// # Safety
///
/// The host maps the argument window at (`arguments`, `len`).
#[unsafe(no_mangle)]
unsafe extern "C" fn vos_refine(arguments: *const u8, len: u64) -> Output {
    // SAFETY: see the function's contract.
    let arguments = unsafe { core::slice::from_raw_parts(arguments, len as usize) };
    Output::leak(refine::run(arguments))
}

/// # Safety
///
/// The host maps the argument window at (`arguments`, `len`).
#[unsafe(no_mangle)]
unsafe extern "C" fn vos_accumulate(arguments: *const u8, len: u64) -> Output {
    // SAFETY: see the function's contract.
    let arguments = unsafe { core::slice::from_raw_parts(arguments, len as usize) };
    accumulate::run(arguments);
    Output { address: 0, len: 0 }
}
