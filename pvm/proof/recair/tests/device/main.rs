//! The device profile's masked segment (`vos_pvm_proof::device`): a
//! kernel's whole run proved masked over the shared chip set without the
//! page boundary, verified against its program; the Poseidon2 chip;
//! and their forgery and leakage gates.

#[path = "../common/mod.rs"]
mod common;

mod format;
mod gates;
mod leakage;
mod program;
mod support;
