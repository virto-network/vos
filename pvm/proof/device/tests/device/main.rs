//! The device profile's masked segment (`vos_pvm_proof::device`,
//! `vos_pvm_device::masked`): a
//! kernel's whole run proved masked over the shared chip set without the
//! page boundary, verified against its program; the Poseidon2 chip;
//! and their forgery, masking and leakage gates.

/// The leakage gates' statistics, the recursion prover's tests' own.
#[path = "../../../recair/tests/common/leakage.rs"]
#[allow(dead_code, reason = "the recursion's leakage gates read the rest")]
mod statistics;

mod cpu;
mod format;
mod gates;
mod leakage;
mod masking;
mod memory;
mod program;
mod support;
