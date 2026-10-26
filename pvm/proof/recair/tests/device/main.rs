//! The device profile's masked segment (`vos_pvm_proof::device`, pin J): a
//! kernel's whole run proved masked over the shared chip set without the
//! page boundary, verified against its program; the Poseidon2 chip (pin H);
//! and their forgery and leakage gates.

#[path = "../common/mod.rs"]
mod common;

mod gates;
mod leakage;
mod support;
