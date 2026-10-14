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

use alloc::vec::Vec;
use core::mem::ManuallyDrop;

// The heap holds a batch's overlays and its work result, up to 4 MiB.
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

/// The halt convention's output: address in φ7, length in φ8.
#[repr(C)]
pub struct Output {
    address: u64,
    len: u64,
}

fn output(bytes: Vec<u8>) -> Output {
    let bytes = ManuallyDrop::new(bytes);
    Output {
        address: bytes.as_ptr() as u64,
        len: bytes.len() as u64,
    }
}

/// # Safety
///
/// The host maps the argument window at (`arguments`, `len`).
#[unsafe(no_mangle)]
unsafe extern "C" fn vos_refine(arguments: *const u8, len: u64) -> Output {
    // SAFETY: see the function's contract.
    let arguments = unsafe { core::slice::from_raw_parts(arguments, len as usize) };
    output(refine::run(arguments))
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
